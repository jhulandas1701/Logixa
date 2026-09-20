package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type MinioStore struct {
	Client *minio.Client
	Bucket string
}
type ProcessingJob struct {
	IngestionID string `json:"ingestion_id"`
	ObjectName  string `json:"object_name"`
	Filename    string `json:"filename"`
}
type IngestionState struct {
	ID            string     `json:"ingestion_id"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	ReceivedFiles int        `json:"received_files"`
	StoredFiles   int        `json:"stored_files"`
	FailedFiles   int        `json:"failed_files"`
	Notifications int        `json:"notifications_sent"`
	FailedNotify  int        `json:"notifications_failed"`
	Status        string     `json:"status"`
}

var stateMu sync.RWMutex
var states = map[string]*IngestionState{}

func main() {
	maxFileSize := envInt64("MAX_FILE_SIZE_MB", 500) * 1024 * 1024
	maxRequestSize := envInt64("MAX_REQUEST_SIZE_GB", 5) * 1024 * 1024 * 1024
	pipelineURL := env("PIPELINE_URL", "http://localhost:8000")
	store, err := newMinioStore(env("MINIO_ENDPOINT", "localhost:9000"), env("MINIO_ACCESS_KEY", "minioadmin"), env("MINIO_SECRET_KEY", "minioadmin"), env("MINIO_BUCKET", "logixa-raw"), envBool("MINIO_SECURE", false))
	if err != nil {
		log.Fatalf("MinIO initialization failed: %v", err)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"service": "logixa-go-ingestor", "status": "ok"}) })
	r.POST("/api/v1/ingest/files", func(c *gin.Context) { handleMultiFileUpload(c, store, pipelineURL, maxFileSize, maxRequestSize) })
	r.GET("/api/v1/ingest/:id", func(c *gin.Context) {
		id := c.Param("id")
		stateMu.RLock()
		st, ok := states[id]
		if ok {
			cp := *st
			stateMu.RUnlock()
			c.JSON(http.StatusOK, cp)
			return
		}
		stateMu.RUnlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "ingestion not found"})
	})
	log.Println("Logixa Go ingestion service listening on :8080")
	log.Fatal(r.Run(":8080"))
}

func handleMultiFileUpload(c *gin.Context, store *MinioStore, pipelineURL string, maxFileSize, maxRequestSize int64) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestSize)
	reader, err := c.Request.MultipartReader()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart/form-data is required"})
		return
	}
	id := fmt.Sprintf("ING-%d", time.Now().UnixNano())
	st := &IngestionState{ID: id, StartedAt: time.Now().UTC(), Status: "uploading"}
	stateMu.Lock()
	states[id] = st
	stateMu.Unlock()
	var uploaded, failed []gin.H
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			updateState(id, func(s *IngestionState) { s.Status = "failed" })
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read multipart request"})
			return
		}
		if part.FileName() == "" {
			continue
		}
		filename := filepath.Base(part.FileName())
		if filename == "." || filename == ".." || filename == "" {
			continue
		}
		updateState(id, func(s *IngestionState) { s.ReceivedFiles++ })
		objectName := fmt.Sprintf("raw/%s/%d_%s", id, time.Now().UnixNano(), filename)
		limited := &countingLimitReader{R: part, N: maxFileSize + 1}
		contentType := part.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		err = store.Upload(c.Request.Context(), objectName, limited, -1, contentType)
		if err != nil {
			updateState(id, func(s *IngestionState) { s.FailedFiles++ })
			failed = append(failed, gin.H{"filename": filename, "error": err.Error()})
			continue
		}
		if limited.Count > maxFileSize {
			_ = store.Remove(c.Request.Context(), objectName)
			updateState(id, func(s *IngestionState) { s.FailedFiles++ })
			failed = append(failed, gin.H{"filename": filename, "error": "file exceeds configured maximum"})
			continue
		}
		updateState(id, func(s *IngestionState) { s.StoredFiles++ })
		job := ProcessingJob{IngestionID: id, ObjectName: objectName, Filename: filename}
		go notifyPipeline(pipelineURL, job, id)
		uploaded = append(uploaded, gin.H{"filename": filename, "object_name": objectName, "ingestion_id": id, "status": "uploaded"})
	}
	now := time.Now().UTC()
	updateState(id, func(s *IngestionState) {
		s.CompletedAt = &now
		if s.FailedFiles > 0 {
			s.Status = "completed_with_errors"
		} else {
			s.Status = "accepted_for_processing"
		}
	})
	c.JSON(http.StatusAccepted, gin.H{"status": "accepted", "ingestion_id": id, "uploaded_files": uploaded, "failed_files": failed, "processing": "asynchronous", "raw_storage": "minio"})
}

type countingLimitReader struct {
	R     io.Reader
	N     int64
	Count int64
}

func (r *countingLimitReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.N {
		p = p[:r.N]
	}
	n, err := r.R.Read(p)
	r.N -= int64(n)
	r.Count += int64(n)
	return n, err
}

func notifyPipeline(url string, job ProcessingJob, id string) {
	var last error
	for attempt := 1; attempt <= 5; attempt++ {
		if err := postJSON(url+"/internal/process", job); err == nil {
			updateState(id, func(s *IngestionState) { s.Notifications++ })
			return
		} else {
			last = err
		}
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	log.Printf("pipeline notification failed for %s: %v", job.ObjectName, last)
	updateState(id, func(s *IngestionState) { s.FailedNotify++ })
}
func postJSON(url string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("pipeline returned HTTP %d", resp.StatusCode)
	}
	return nil
}
func updateState(id string, fn func(*IngestionState)) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if s, ok := states[id]; ok {
		fn(s)
	}
}
func (s *MinioStore) Upload(ctx context.Context, name string, r io.Reader, size int64, ct string) error {
	_, err := s.Client.PutObject(ctx, s.Bucket, name, r, size, minio.PutObjectOptions{ContentType: ct})
	return err
}
func (s *MinioStore) Remove(ctx context.Context, name string) error {
	return s.Client.RemoveObject(ctx, s.Bucket, name, minio.RemoveObjectOptions{})
}
func newMinioStore(endpoint, access, secret, bucket string, secure bool) (*MinioStore, error) {
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: secure})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		exists, e := client.BucketExists(ctx, bucket)
		if e == nil {
			if !exists {
				if e = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); e != nil {
					return nil, e
				}
			}
			return &MinioStore{Client: client, Bucket: bucket}, nil
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("MinIO not ready")
}
func env(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}
func envInt64(k string, f int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, e := strconv.ParseInt(v, 10, 64); e == nil {
			return n
		}
	}
	return f
}
func envBool(k string, f bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			return b
		}
	}
	return f
}
