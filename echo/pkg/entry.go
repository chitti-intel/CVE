package root

type Report struct {
	Matches []Match `json:"matches"`
}
type Match struct {
	CVE      string      `json:"cve"`
	Package  string      `json:"package"`
	Version  string      `json:"version"`
	Severity string      `json:"severity"`
	Cvss     []CvssEntry `json:"cvss"`
}

type CvssEntry struct {
	Version             string `json:"version"`
	BaseScore           string `json:"baseScore"`
	ExploitabilityScore string `json:"exploitabilityScore"`
	ImpactScore         string `json:"impactScore"`
}

type Entry struct {
	Id        string `json:"id"`
	Uuid      string
	Name      string
	Digest    string
	Timestamp string
	SbomPath  string
	CVE       *Report
}

type EntryService interface {
	Create(e *Entry) error
	GetByUuid(username string) (*Entry, error)
	Exists(digest string) (bool, error)
}
