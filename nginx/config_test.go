package nginx

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deis/router/model"
)

func TestWriteCerts(t *testing.T) {
	sslPath, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(sslPath)

	// Create an extra crt/key pair to ensure they are correctly removed.
	certPath := filepath.Join(sslPath, "extra.crt")
	clientCertPath := filepath.Join(sslPath, "extra.client.ca.crt")
	keyPath := filepath.Join(sslPath, "extra.key")
	err = ioutil.WriteFile(certPath, []byte("foo"), 0644)
	if err != nil {
		t.Error(err)
	}
	err = ioutil.WriteFile(certPath, []byte("bar"), 0644)
	if err != nil {
		t.Error(err)
	}
	err = ioutil.WriteFile(keyPath, []byte("qux"), 0600)
	if err != nil {
		t.Error(err)
	}

	expectedPlatformCrt := "platform-biz"
	expectedPlatformKey := "platform-baz"
	expectedExampleCrt := "examplecom-crt"
	expectedExampleKey := "examplecom-key"
	expectedClientCert := "qwert\nyuiop\nasd\nfgh\njkl"
	routerConfig := model.RouterConfig{
		PlatformCertificate: &model.Certificate{
			Cert: expectedPlatformCrt,
			Key:  expectedPlatformKey,
		},
		AppConfigs: []*model.AppConfig{
			&model.AppConfig{
				Certificates: map[string]*model.Certificate{
					"example.com": &model.Certificate{
						Cert: expectedExampleCrt,
						Key:  expectedExampleKey,
					},
				},
			},
		},
		ClientCertificates: []string{
			"qwert\nyuiop",
			"asd\nfgh\njkl",
		},
	}

	WriteCerts(&routerConfig, sslPath)

	// Any extra crt/key files should be removed.
	if _, err2 := os.Stat(certPath); err2 == nil {
		t.Errorf("Expected extra.crt to be removed, but the file was found.")
	}
	if _, err2 := os.Stat(clientCertPath); err2 == nil {
		t.Errorf("Expected extra.client.ca.crt to be removed, but the file was found.")
	}
	if _, err2 := os.Stat(keyPath); err2 == nil {
		t.Errorf("Expected extra.key to be removed, but the file was found.")
	}

	// platform.crt and platform.key should exist with correct permissions and contents.
	platformCrtPath := filepath.Join(sslPath, "platform.crt")
	platformKeyPath := filepath.Join(sslPath, "platform.key")
	err = checkCertAndKey(platformCrtPath, platformKeyPath, expectedPlatformCrt, expectedPlatformKey)
	if err != nil {
		t.Error(err)
	}

	// example application crt and key should exist with correct permissions and contents.
	exampleCrtPath := filepath.Join(sslPath, "example.com.crt")
	exampleKeyPath := filepath.Join(sslPath, "example.com.key")
	err = checkCertAndKey(exampleCrtPath, exampleKeyPath, expectedExampleCrt, expectedExampleKey)
	if err != nil {
		t.Error(err)
	}

	// example client crt should exist with correct permissions and contents.
	clientCrtPath := filepath.Join(sslPath, "client.ca.crt")
	err = checkCert(clientCrtPath, expectedClientCert)
	if err != nil {
		t.Error(err)
	}
}

func TestWriteCert(t *testing.T) {
	// Ensure cert/key are written with correct contents and correct permissions.
	expectedCertContents := "foo"
	expectedKeyContents := "bar"
	certificate := model.Certificate{
		Cert: expectedCertContents,
		Key:  expectedKeyContents,
	}

	sslPath, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(sslPath)
	crtPath := filepath.Join(sslPath, "test.crt")
	keyPath := filepath.Join(sslPath, "test.key")

	err = writeCert("test", &certificate, sslPath)
	if err != nil {
		t.Error(err)
	}

	err = checkCertAndKey(crtPath, keyPath, expectedCertContents, expectedKeyContents)
	if err != nil {
		t.Error(err)
	}
}

func TestWriteDHParam(t *testing.T) {
	// Ensure sslPath/dhparam.pem exists with the contents of routerConfig.SSLConfig.DHParam and is 0644
	sslPath, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(sslPath)
	dhParamPath := filepath.Join(sslPath, "dhparam.pem")

	expectedDHParam := "bizbar"
	routerConfig := model.RouterConfig{
		SSLConfig: &model.SSLConfig{
			DHParam: expectedDHParam,
		},
	}

	err = WriteDHParam(&routerConfig, sslPath)
	if err != nil {
		t.Error(err)
	}

	actualDHParam, err := ioutil.ReadFile(dhParamPath)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(expectedDHParam, string(actualDHParam)) {
		t.Errorf("Expected dhparam.pem contents, %s, does not match actual contents, %s.", expectedDHParam, string(actualDHParam))
	}

	expectedPerm := "-rw-r--r--" // 0644

	info, _ := os.Stat(dhParamPath)
	actualPerm := info.Mode().String()
	if !reflect.DeepEqual(expectedPerm, actualPerm) {
		t.Errorf("Expected permission on dhparam.pem, %s, does not match actual, %s.", expectedPerm, actualPerm)
	}

	// Ensure dhparam.pem is erased when routerConfig.SSLConfig.DHParam is empty
	sslPath, err = ioutil.TempDir("", "test-empty")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(sslPath)
	dhParamPath = filepath.Join(sslPath, "dhparam.pem")

	routerConfig = model.RouterConfig{
		SSLConfig: &model.SSLConfig{
			DHParam: "",
		},
	}
	err = WriteDHParam(&routerConfig, sslPath)
	if err != nil {
		t.Error(err)
	}

	if _, err := os.Stat(dhParamPath); err == nil {
		t.Errorf("Expected dhparam.pem to be erased when DHParam was an empty string, but the file was found.")
	}
}

func TestWriteConfig(t *testing.T) {
	routerConfig := model.RouterConfig{}
	routerConfig.GzipConfig = &model.GzipConfig{}
	routerConfig.SSLConfig = &model.SSLConfig{}
	routerConfig.SSLConfig.HSTSConfig = &model.HSTSConfig{}

	tmpFile, err := ioutil.TempFile("", "test")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpFile.Name())

	err = WriteConfig(&routerConfig, tmpFile.Name())
	if err != nil {
		t.Error("Config template engine failed:", err)
	}

	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Errorf("Expected to find nginx config file. No file found.")
	}
}

func checkCertAndKey(crtPath string, keyPath string, expectedCertContents string, expectedKeyContents string) error {
	err := checkCert(crtPath, expectedCertContents)
	if err != nil {
		return err
	}
	err2 := checkKey(keyPath, expectedKeyContents)
	if err2 != nil {
		return err2
	}

	return nil
}

func checkCert(crtPath string, expectedCertContents string) error {
	actualCertContents, err := ioutil.ReadFile(crtPath)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(expectedCertContents, string(actualCertContents)) {
		return fmt.Errorf("Expected test.crt contents, %s, does not match actual contents, %s.", expectedCertContents, string(actualCertContents))
	}

	expectedCertPerm := "-rw-r--r--" // 0644

	crtInfo, _ := os.Stat(crtPath)
	actualCertPerm := crtInfo.Mode().String()
	if !reflect.DeepEqual(expectedCertPerm, actualCertPerm) {
		return fmt.Errorf("Expected permission on test.crt, %s, does not match actual, %s.", expectedCertPerm, actualCertPerm)
	}

	return nil
}

func checkKey(keyPath string, expectedKeyContents string) error {
	actualKeyContents, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expectedKeyContents, string(actualKeyContents)) {
		return fmt.Errorf("Expected test.key contents, %s, does not match actual contents, %s.", expectedKeyContents, string(actualKeyContents))
	}

	expectedKeyPerm := "-rw-------" // 0600

	keyInfo, _ := os.Stat(keyPath)
	actualKeyPerm := keyInfo.Mode().String()
	if !reflect.DeepEqual(expectedKeyPerm, actualKeyPerm) {
		return fmt.Errorf("Expected permission on test.key, %s, does not match actual, %s.", expectedKeyPerm, actualKeyPerm)
	}

	return nil
}
