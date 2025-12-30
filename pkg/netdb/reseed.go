package netdb

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-i2p/go-i2p/pkg/data"
)

// Reseed constants
const (
	ReseedHTTPTimeout = 30 * time.Second
	MinReseedRouters  = 10
)

// DefaultReseedHosts are the default reseed servers.
var DefaultReseedHosts = []string{
	"https://reseed.i2p-projekt.de/",
	"https://i2p.mooo.com/netDb/",
	"https://reseed.i2p.net.in/",
	"https://reseed.onion.im/",
	"https://reseed-fr.i2pd.xyz/",
	"https://reseed.memcpy.io/",
	"https://reseed.atomike.ninja/",
}

// Reseeder handles reseeding the network database.
type Reseeder struct {
	hosts     []string
	netDb     *NetDb
	trustedCerts []*x509.Certificate
}

// NewReseeder creates a new reseeder.
func NewReseeder(netDb *NetDb) *Reseeder {
	return &Reseeder{
		hosts: DefaultReseedHosts,
		netDb: netDb,
	}
}

// SetHosts sets custom reseed hosts.
func (r *Reseeder) SetHosts(hosts []string) {
	r.hosts = hosts
}

// Reseed performs a reseed operation.
func (r *Reseeder) Reseed() (int, error) {
	var lastErr error
	totalImported := 0

	for _, host := range r.hosts {
		imported, err := r.reseedFromHost(host)
		if err != nil {
			lastErr = err
			continue
		}

		totalImported += imported
		if totalImported >= MinReseedRouters {
			return totalImported, nil
		}
	}

	if totalImported == 0 && lastErr != nil {
		return 0, lastErr
	}

	return totalImported, nil
}

// reseedFromHost attempts to reseed from a single host.
func (r *Reseeder) reseedFromHost(host string) (int, error) {
	// Try i2pseeds.su3 first
	su3URL := host
	if !strings.HasSuffix(su3URL, "/") {
		su3URL += "/"
	}
	su3URL += "i2pseeds.su3"

	// Fetch the SU3 file
	client := &http.Client{
		Timeout: ReseedHTTPTimeout,
	}

	resp, err := client.Get(su3URL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("reseed: HTTP error: " + resp.Status)
	}

	// Read the SU3 file
	su3Data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	// Parse and extract RouterInfos
	return r.parseSU3(su3Data)
}

// parseSU3 parses an SU3 file and extracts RouterInfos.
func (r *Reseeder) parseSU3(data []byte) (int, error) {
	// SU3 file format:
	// - Magic number: "I2Psu3" (6 bytes)
	// - Unused: 1 byte
	// - SU3 file format version: 1 byte (always 0)
	// - Signature type: 2 bytes (big-endian)
	// - Signature length: 2 bytes (big-endian)
	// - Unused: 1 byte
	// - Version length: 1 byte
	// - Unused: 1 byte
	// - Signer ID length: 1 byte
	// - Content length: 8 bytes (big-endian)
	// - Unused: 1 byte
	// - File type: 1 byte (0=zip, 1=xml, 2=html, 3=xml.gz, 4=txt.gz)
	// - Unused: 1 byte
	// - Content type: 1 byte (0=unknown, 1=router_update, 2=plugin, 3=reseed)
	// ... followed by version, signer ID, content, and signature

	if len(data) < 40 {
		return 0, errors.New("reseed: SU3 file too short")
	}

	// Check magic number
	if string(data[0:6]) != "I2Psu3" {
		return 0, errors.New("reseed: invalid SU3 magic number")
	}

	// Parse header
	sigLen := int(data[8])<<8 | int(data[9])
	versionLen := int(data[11])
	signerLen := int(data[13])
	contentLen := int64(data[14])<<56 | int64(data[15])<<48 | int64(data[16])<<40 | int64(data[17])<<32 |
		int64(data[18])<<24 | int64(data[19])<<16 | int64(data[20])<<8 | int64(data[21])
	fileType := data[23]
	contentType := data[25]

	// Verify content type is reseed (3)
	if contentType != 3 {
		return 0, errors.New("reseed: invalid content type")
	}

	// Verify file type is zip (0)
	if fileType != 0 {
		return 0, errors.New("reseed: invalid file type (expected zip)")
	}

	// Calculate content offset
	headerSize := 40 + versionLen + signerLen
	if int64(len(data)) < int64(headerSize)+contentLen+int64(sigLen) {
		return 0, errors.New("reseed: SU3 file incomplete")
	}

	// Extract the zip content
	zipData := data[headerSize : int64(headerSize)+contentLen]

	// TODO: Verify signature
	// For now, we skip signature verification

	// Parse zip file
	return r.extractRouterInfos(zipData)
}

// extractRouterInfos extracts RouterInfo entries from a zip file.
func (r *Reseeder) extractRouterInfos(zipData []byte) (int, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return 0, err
	}

	imported := 0

	for _, file := range reader.File {
		// RouterInfo files are named routerInfo-<base64hash>.dat
		if !strings.HasPrefix(file.Name, "routerInfo-") || !strings.HasSuffix(file.Name, ".dat") {
			continue
		}

		// Open the file
		rc, err := file.Open()
		if err != nil {
			continue
		}

		// Read the RouterInfo data
		riData, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		// Parse the RouterInfo
		ri, err := data.NewRouterInfo(riData)
		if err != nil {
			continue
		}

		// Verify the RouterInfo
		if !ri.Verify() {
			continue
		}

		// Store in the database
		if err := r.netDb.StoreRouterInfo(ri); err != nil {
			continue
		}

		imported++
	}

	return imported, nil
}

// ReseedFromFile reseeds from a local SU3 file.
func (r *Reseeder) ReseedFromFile(path string) (int, error) {
	// Would read and parse file
	return 0, errors.New("reseed: file reseed not implemented")
}

// NeedsReseed returns true if the database needs reseeding.
func (r *Reseeder) NeedsReseed() bool {
	return r.netDb.RouterInfoCount() < MinReseedRouters
}
