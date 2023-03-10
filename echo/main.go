package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"echo/pkg"
	"echo/pkg/cve"
	"echo/pkg/mongo"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var c *mongo.Client
var entryService *mongo.EntryService

const (
	mongoUrl            = "mongodb://my-release-mongodb.default.svc.cluster.local:27017"
	dbName              = "prod_cve_db"
	entryCollectionName = "cve_entry"
)

type Server struct {
}

type UuidInfo struct {
	Uuid      string `json:"uuid"`
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	TimeStamp string `json:"timestamp"`
}

type PostResponse struct {
	Uuids  []UuidInfo  `json:"uuids"`
	Report root.Report `json:"report"`
}

type GetAllResponse struct {
	Uuids []UuidInfo `json:"uuids"`
}

// (POST /api/v1/cve-reports)
func (si Server) PostApiV1CveReports(ctx echo.Context) error {
	// Read form fields
	var sbomPath, uuid, timeStamp string
	var cveReport []root.Match
	var report *root.Report
	inputType := ctx.FormValue("inputType")
	name := ctx.FormValue("name")
	digest := ctx.FormValue("digest")

	//------------
	// Read files
	//------------

	// Multipart form
	form, err := ctx.MultipartForm()
	if err != nil {
		return err
	}

	//check if for the given digest report exists
	check, err := entryService.Exists(digest)

	if check == true {
		// get document from DB
		document, err := entryService.GetByDigest(digest)
		if err != nil {
			return err
		}
		uuid = document.Uuid
		timeStamp = document.Timestamp
		report = document.CVE
	} else {
		// generate and store report
		if inputType != "image" {
			files := form.File["sbomFile"]

			for _, file := range files {
				// Source
				src, err := file.Open()
				if err != nil {
					return err
				}
				defer src.Close()

				// Destination
				sbomPath = "/tmp/" + file.Filename
				dst, err := os.Create(sbomPath)
				if err != nil {
					return err
				}
				defer dst.Close()

				// Copy
				if _, err = io.Copy(dst, src); err != nil {
					return err
				}

			}

			cveReport, err = generateCVEReport(inputType, sbomPath)

		} else {
			cveReport, err = generateCVEReport(inputType, name)
		}

		if err != nil {
			return err
		}

		report = &root.Report{
			Matches: cveReport,
		}

		//store in DB
		uuid = generateUuid()
		timeStamp = generateTimeStamp()
		err = storeInDB(uuid, name, digest, timeStamp, sbomPath, report)
	}

	fmt.Println(report)
	response := &PostResponse{
		Uuids: []UuidInfo{
			{
				Uuid:      uuid,
				Name:      name,
				Digest:    digest,
				TimeStamp: timeStamp,
			},
		},
		Report: *report,
	}

	return ctx.JSON(http.StatusOK, response)
}

func (si Server) GetApiV1CveReports(ctx echo.Context, params cve.GetApiV1CveReportsParams) error {

	var uuids []UuidInfo
	digest := params.Digest
	name := params.Name

	if digest == nil && name == nil {
		documents, err := entryService.GetAll()
		if err != nil {
			return err
		}

		for _, document := range documents {
			var elem UuidInfo
			elem.Uuid = document.Uuid
			elem.Name = document.Name
			elem.Digest = document.Digest
			elem.TimeStamp = document.Timestamp

			uuids = append(uuids, elem)
		}
	} else if digest != nil {
		document, err := entryService.GetByDigest(*digest)
		if err != nil {
			return err
		}
		uuids = []UuidInfo{
			{
				Uuid:      document.Uuid,
				Name:      document.Name,
				Digest:    document.Digest,
				TimeStamp: document.Timestamp,
			},
		}
	} else {
		documents, err := entryService.GetAllbyName(*name)
		if err != nil {
			return err
		}

		for _, document := range documents {
			var elem UuidInfo
			elem.Uuid = document.Uuid
			elem.Name = document.Name
			elem.Digest = document.Digest
			elem.TimeStamp = document.Timestamp

			uuids = append(uuids, elem)
		}
	}

	response := &GetAllResponse{
		Uuids: uuids,
	}

	return ctx.JSON(http.StatusOK, response)
}
func (si Server) GetApiV1CveReportsUuid(ctx echo.Context, uuid string, params cve.GetApiV1CveReportsUuidParams) error {

	var flag bool
	var version_float, cvss_float float64
	var filtererd_report *root.Report
	version := params.Version
	if version != nil {
		version_float, _ = strconv.ParseFloat(*version, 64)
	}
	cvss_score := params.Cvss
	if cvss_score != nil {
		cvss_float, _ = strconv.ParseFloat(*cvss_score, 64)
	}
	// get the document from db
	document, err := entryService.GetByUuid(uuid)
	if err != nil {
		return err
	}
	name := document.Name
	digest := document.Digest
	timeStamp := document.Timestamp
	report := document.CVE

	if version != nil || cvss_score != nil {
		var filetered_matches []root.Match
		for _, match := range report.Matches {
			flag = false
			var filetered_cvss []root.CvssEntry
			for _, cvss_object := range match.Cvss {
				unit_version, err := strconv.ParseFloat(cvss_object.Version, 64)
				if err != nil {
					return err
				}
				unit_cvss, err := strconv.ParseFloat(cvss_object.BaseScore, 64)
				if err != nil {
					return err
				}

				if version != nil && cvss_score != nil {
					if unit_version == version_float && unit_cvss >= cvss_float {
						filetered_cvss = append(filetered_cvss, cvss_object)
						flag = true
					}
				} else if cvss_score != nil {
					if unit_cvss >= cvss_float {
						filetered_cvss = append(filetered_cvss, cvss_object)
						flag = true
					}
				} else {
					if unit_version == version_float {
						filetered_cvss = append(filetered_cvss, cvss_object)
						flag = true
					}
				}
				if flag {
					var elem root.Match
					elem.CVE = match.CVE
					elem.Package = match.Package
					elem.Version = match.Version
					elem.Severity = match.Severity
					elem.Cvss = filetered_cvss
					filetered_matches = append(filetered_matches, elem)
				}
			}
		}
		filtererd_report = &root.Report{
			Matches: filetered_matches,
		}
	} else {
		filtererd_report = report
	}

	response := &PostResponse{
		Uuids: []UuidInfo{
			{
				Uuid:      uuid,
				Name:      name,
				Digest:    digest,
				TimeStamp: timeStamp,
			},
		},
		Report: *filtererd_report,
	}
	return ctx.JSON(http.StatusOK, response)
}

func generateCVEReport(inputType, name string) ([]root.Match, error) {

	var argSuffix string
	if inputType == "image" {
		argSuffix = "grype " + name
	} else {
		argSuffix = "grype sbom:" + name
	}

	argstring := argSuffix + ` --add-cpes-if-none -o template -t ./cve-json.tmpl`
	outcveresult, err := exec.Command("sh", "-c", argstring).Output()
	if err != nil {
		return nil, err
	}
	var matches []root.Match

	err = json.Unmarshal(outcveresult, &matches)
	if err != nil {
		return nil, err
	}

	return matches, nil
}

func storeInDB(uuid, name, digest, timeStamp, sbomPath string, CVEReport *root.Report) error {
	entry := root.Entry{
		Uuid:      uuid,
		Name:      name,
		Digest:    digest,
		Timestamp: timeStamp,
		SbomPath:  sbomPath,
		CVE:       CVEReport,
	}
	//Act
	_, err := entryService.Create(&entry)

	//Assert
	if err != nil {
		return err
	}

	return nil
}

func generateUuid() string {
	return uuid.New().String()
}

func generateTimeStamp() string {
	return time.Now().Format(time.RFC3339)
}
func main() {
	s := Server{}
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Obtain mongo client
	c, err := mongo.GetClient(mongoUrl)
	if err != nil {
		log.Fatalf("Unable to connect to mongo: %s\n", err)
	}
	defer func() {
		err = c.Disconnect()
		if err != nil {
			log.Fatal(err)
		}
	}()

	//Obtain handle to EntryService which has pointer to the collection
	entryService, err = mongo.NewEntryService(c, dbName, entryCollectionName)
	if err != nil {
		log.Fatal(err)
	}

	cve.RegisterHandlers(e, s)

	e.Logger.Fatal(e.Start(":1323"))
}
