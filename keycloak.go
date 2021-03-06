package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cenkalti/backoff"
	"io/ioutil"
	"net/http"
	"crypto/tls"
)

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	SessionState     string `json:"session_state"`
	NotBeforePolicy  int    `json:"not-before-policy"`
}

func authenticate(realm string, endpoint string, username string, password string, clientID string, clientSecret string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	postBody := []byte("username=" + username + "&password=" + password + "&client_id=" + clientID + "&client_secret=" + clientSecret + "&grant_type=password")
	resp, err := client.Post(
		endpoint+"/realms/" + realm + "/protocol/openid-connect/token",
		"application/x-www-form-urlencoded",
		bytes.NewBuffer(postBody),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		return "", backoff.Permanent(fmt.Errorf("Failed to authenticate with statusCode %d: %s", resp.StatusCode, resp.Status))
	}
	if resp.StatusCode >= 500 {
		return "", fmt.Errorf("Failed to authenticate with statusCode %d: %s", resp.StatusCode, resp.Status)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("[DEBUG] Response Body: %s\n", buf)
	if err != nil {
		return "", backoff.Permanent(err)
	}

	var tokenResponse tokenResponse
	err = json.Unmarshal(buf, &tokenResponse)
	if err != nil {
		return "", backoff.Permanent(err)
	}

	return tokenResponse.AccessToken, nil
}

type userRepresentation struct {
	CreatedTimestamp int64  `json:"createdTimestamp"`
	Email            string `json:"email"`
	EmailVerified    bool   `json:"emailVerified"`
	Enabled          bool   `json:"enabled"`
	ID               string `json:"id"`
	Username         string `json:"username"`
}

func getUserList(realm string, endpoint string, token string) ([]string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	groupID, err := getDataSubjectsGroupId(realm, endpoint, token);
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", endpoint+"/admin/realms/" + realm + "/groups/" + groupID + "/members", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		return nil, backoff.Permanent(fmt.Errorf("Failed to retrieve userList with statusCode %d: %s", resp.StatusCode, resp.Status))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("Failed to retrieve userList with statusCode %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("[DEBUG] Response Body: %s\n", body)
	if err != nil {
		return nil, backoff.Permanent(err)
	}

	var userRepresentations []userRepresentation
	err = json.Unmarshal(body, &userRepresentations)
	if err != nil {
		return nil, backoff.Permanent(err)
	}

	var userList []string
	for _, user := range userRepresentations {
		if user.Enabled {
			userList = append(userList, user.ID)
		}
	}
	return userList, nil
}

type groupRepresentation struct {
	ID               string `json:"id"`
	Name         string `json:"name"`
}
func getDataSubjectsGroupId(realm string, endpoint string, token string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", endpoint+"/admin/realms/" + realm + "/groups?search=data-subjects", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		return "", backoff.Permanent(fmt.Errorf("Failed to retrieve data subjects group with statusCode %d: %s", resp.StatusCode, resp.Status))
	}
	if resp.StatusCode >= 500 {
		return "", fmt.Errorf("Failed to retrieve data subjects group with statusCode %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("[DEBUG] Response Body: %s\n", body)
	if err != nil {
		return "", backoff.Permanent(err)
	}

	var groupRepresentations []groupRepresentation
	err = json.Unmarshal(body, &groupRepresentations)
	if err != nil {
		return "", backoff.Permanent(err)
	}

	if len(groupRepresentations) <= 0 {
		return "", fmt.Errorf("Failed to retrieve data subjects group")
	}
	return groupRepresentations[0].ID, nil
}

type applicationListResponse struct {
	Applications []policy `json:"applications"`
}

type policyListResponse struct {
	Policies []simplepolicy `json:"policies"`
}

func getApplicationPolicies(endpoint string, token string) ([]policy, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", endpoint+"/applications/", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		return nil, backoff.Permanent(fmt.Errorf("Failed to retrieve application policies with statusCode %d: %s", resp.StatusCode, resp.Status))
	}
	if resp.StatusCode > 500 {
		return nil, fmt.Errorf("Failed to retrieve application policies with statusCode %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, backoff.Permanent(err)
	}

	var applications applicationListResponse
	err = json.Unmarshal(body, &applications)
	if err != nil {
		return nil, backoff.Permanent(err)
	}

	for i, application := range applications.Applications {
		req, err = http.NewRequest("GET", endpoint+"/applications/"+application.ID+"/policies", nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 500 {
			return nil, backoff.Permanent(fmt.Errorf("Failed to retrieve application policies with statusCode %d: %s", resp.StatusCode, resp.Status))
		}
		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("Failed to retrieve application policies with statusCode %d: %s", resp.StatusCode, resp.Status)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, backoff.Permanent(err)
		}

		var simplepolicies policyListResponse
		err = json.Unmarshal(body, &simplepolicies)
		if err != nil {
			return nil, backoff.Permanent(err)
		}
		applications.Applications[i].SimplePolicies = simplepolicies.Policies
	}

	return applications.Applications, nil
}
