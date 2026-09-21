package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
)

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

	maxFileSize := envInt64(
		"MAX_FILE_SIZE_MB",
		500,
	) * 1024 * 1024

	maxRequestSize := envInt64(
		"MAX_REQUEST_SIZE_GB",
		5,
	) * 1024 * 1024 * 1024

	pipelineURL := env(
		"PIPELINE_URL",
		"http://localhost:8000",
	)

	r := gin.New()

	r.Use(gin.Logger(), gin.Recovery())

	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"https://logixa-three.vercel.app",
		},
		AllowMethods: []string{
			"GET",
			"POST",
			"OPTIONS",
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
		},
	}))

	// --------------------------------------------------
	// HEALTH CHECK
	// --------------------------------------------------

	r.GET("/health", func(c *gin.Context) {

		c.JSON(http.StatusOK, gin.H{
			"service": "logixa-go-ingestor",
			"status":  "ok",
		})
	})

	// --------------------------------------------------
	// FILE INGESTION
	// --------------------------------------------------

	r.POST(
		"/api/v1/ingest/files",
		func(c *gin.Context) {

			handleMultiFileUpload(
				c,
				pipelineURL,
				maxFileSize,
				maxRequestSize,
			)
		},
	)

	// --------------------------------------------------
	// INGESTION STATUS
	// --------------------------------------------------

	r.GET(
		"/api/v1/ingest/:id",
		func(c *gin.Context) {

			id := c.Param("id")

			stateMu.RLock()

			st, ok := states[id]

			if ok {
				cp := *st

				stateMu.RUnlock()

				c.JSON(
					http.StatusOK,
					cp,
				)

				return
			}

			stateMu.RUnlock()

			c.JSON(
				http.StatusNotFound,
				gin.H{
					"error": "ingestion not found",
				},
			)
		},
	)

	log.Println(
		"Logixa Go ingestion service listening on :8080",
	)

	log.Fatal(
		r.Run(":8080"),
	)
}

// ======================================================
// MULTI-FILE UPLOAD
// ======================================================

func handleMultiFileUpload(
	c *gin.Context,
	pipelineURL string,
	maxFileSize int64,
	maxRequestSize int64,
) {

	c.Request.Body = http.MaxBytesReader(
		c.Writer,
		c.Request.Body,
		maxRequestSize,
	)

	reader, err := c.Request.MultipartReader()

	if err != nil {

		c.JSON(
			http.StatusBadRequest,
			gin.H{
				"error": "multipart/form-data is required",
			},
		)

		return
	}

	// --------------------------------------------------
	// CREATE INGESTION ID
	// --------------------------------------------------

	id := fmt.Sprintf(
		"ING-%d",
		time.Now().UnixNano(),
	)

	st := &IngestionState{
		ID:        id,
		StartedAt: time.Now().UTC(),
		Status:    "uploading",
	}

	stateMu.Lock()

	states[id] = st

	stateMu.Unlock()

	var uploaded []gin.H
	var failed []gin.H

	// --------------------------------------------------
	// READ EACH FILE
	// --------------------------------------------------

	for {

		part, err := reader.NextPart()

		if err == io.EOF {
			break
		}

		if err != nil {

			updateState(
				id,
				func(s *IngestionState) {
					s.Status = "failed"
				},
			)

			c.JSON(
				http.StatusBadRequest,
				gin.H{
					"error": "failed to read multipart request",
				},
			)

			return
		}

		// Skip normal form fields.
		if part.FileName() == "" {
			continue
		}

		// --------------------------------------------------
		// SANITIZE FILE NAME
		// --------------------------------------------------

		filename := filepath.Base(
			part.FileName(),
		)

		if filename == "." ||
			filename == ".." ||
			filename == "" {

			continue
		}

		updateState(
			id,
			func(s *IngestionState) {
				s.ReceivedFiles++
			},
		)

		// --------------------------------------------------
		// READ FILE WITH SIZE LIMIT
		// --------------------------------------------------

		limited := &countingLimitReader{
			R: part,
			N: maxFileSize + 1,
		}

		content, err := io.ReadAll(limited)

		if err != nil {

			updateState(
				id,
				func(s *IngestionState) {
					s.FailedFiles++
				},
			)

			failed = append(
				failed,
				gin.H{
					"filename": filename,
					"error":    err.Error(),
				},
			)

			continue
		}

		// --------------------------------------------------
		// FILE TOO LARGE
		// --------------------------------------------------

		if limited.Count > maxFileSize {

			updateState(
				id,
				func(s *IngestionState) {
					s.FailedFiles++
				},
			)

			failed = append(
				failed,
				gin.H{
					"filename": filename,
					"error": "file exceeds configured maximum",
				},
			)

			continue
		}

		// --------------------------------------------------
		// SEND FILE DIRECTLY TO PYTHON
		// --------------------------------------------------

		err = notifyPipeline(
			pipelineURL,
			id,
			filename,
			content,
		)

		if err != nil {

			updateState(
				id,
				func(s *IngestionState) {
					s.FailedFiles++
					s.FailedNotify++
				},
			)

			failed = append(
				failed,
				gin.H{
					"filename": filename,
					"error":    err.Error(),
				},
			)

			continue
		}

		// --------------------------------------------------
		// ACCEPTED BY PYTHON
		// --------------------------------------------------

		updateState(
			id,
			func(s *IngestionState) {
				s.StoredFiles++
				s.Notifications++
			},
		)

		uploaded = append(
			uploaded,
			gin.H{
				"filename":     filename,
				"ingestion_id": id,
				"status":       "accepted_for_processing",
			},
		)
	}

	// --------------------------------------------------
	// FINALIZE INGESTION STATE
	// --------------------------------------------------

	now := time.Now().UTC()

	updateState(
		id,
		func(s *IngestionState) {

			s.CompletedAt = &now

			if s.FailedFiles > 0 {
				s.Status = "completed_with_errors"
			} else {
				s.Status = "accepted_for_processing"
			}
		},
	)

	// --------------------------------------------------
	// RESPONSE
	// --------------------------------------------------

	c.JSON(
		http.StatusAccepted,
		gin.H{
			"status":         "accepted",
			"ingestion_id":   id,
			"uploaded_files": uploaded,
			"failed_files":   failed,
			"processing":     "asynchronous",
			"raw_storage":    "python_local",
			"pipeline":       pipelineURL,
		},
	)
}

// ======================================================
// COUNTING READER
// ======================================================

type countingLimitReader struct {
	R     io.Reader
	N     int64
	Count int64
}

func (r *countingLimitReader) Read(
	p []byte,
) (int, error) {

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

// ======================================================
// SEND FILE TO PYTHON PIPELINE
// ======================================================

func notifyPipeline(
	pipelineURL string,
	ingestionID string,
	filename string,
	content []byte,
) error {

	var lastErr error

	for attempt := 1; attempt <= 5; attempt++ {

		err := postMultipartFile(
			pipelineURL+"/internal/process-file",
			ingestionID,
			filename,
			content,
		)

		if err == nil {
			return nil
		}

		lastErr = err

		time.Sleep(
			time.Duration(attempt) * 500 * time.Millisecond,
		)
	}

	return fmt.Errorf(
		"pipeline notification failed: %v",
		lastErr,
	)
}

// ======================================================
// MULTIPART HTTP REQUEST
// ======================================================

func postMultipartFile(
	url string,
	ingestionID string,
	filename string,
	content []byte,
) error {

	var body bytes.Buffer

	writer := multipart.NewWriter(&body)

	// --------------------------------------------------
	// ingestion_id
	// --------------------------------------------------

	err := writer.WriteField(
		"ingestion_id",
		ingestionID,
	)

	if err != nil {
		return err
	}

	// --------------------------------------------------
	// filename
	// --------------------------------------------------

	err = writer.WriteField(
		"filename",
		filename,
	)

	if err != nil {
		return err
	}

	// --------------------------------------------------
	// file
	// --------------------------------------------------

	part, err := writer.CreateFormFile(
		"file",
		filename,
	)

	if err != nil {
		return err
	}

	_, err = part.Write(content)

	if err != nil {
		return err
	}

	err = writer.Close()

	if err != nil {
		return err
	}

	// --------------------------------------------------
	// HTTP REQUEST
	// --------------------------------------------------

	req, err := http.NewRequest(
		http.MethodPost,
		url,
		&body,
	)

	if err != nil {
		return err
	}

	req.Header.Set(
		"Content-Type",
		writer.FormDataContentType(),
	)

	// --------------------------------------------------
	// SEND
	// --------------------------------------------------

	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 {

		responseBody, _ := io.ReadAll(
			io.LimitReader(resp.Body, 4096),
		)

		return fmt.Errorf(
			"pipeline returned HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(
				string(responseBody),
			),
		)
	}

	return nil
}

// ======================================================
// UPDATE INGESTION STATE
// ======================================================

func updateState(
	id string,
	fn func(*IngestionState),
) {

	stateMu.Lock()

	defer stateMu.Unlock()

	if s, ok := states[id]; ok {
		fn(s)
	}
}

// ======================================================
// ENVIRONMENT HELPERS
// ======================================================

func env(
	key string,
	fallback string,
) string {

	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func envInt64(
	key string,
	fallback int64,
) int64 {

	if value := os.Getenv(key); value != "" {

		if n, err := strconv.ParseInt(
			value,
			10,
			64,
		); err == nil {
			return n
		}
	}

	return fallback
}
