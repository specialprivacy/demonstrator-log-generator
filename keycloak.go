package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cenkalti/backoff"
	"io/ioutil"
	"net/http"
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

func authenticate(endpoint string, username string, password string) (string, error) {
	postBody := []byte("username=" + username + "&password=" + password + "&client_id=admin-cli&grant_type=password")
	resp, err := http.Post(
		endpoint+"/realms/master/protocol/openid-connect/token",
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

func getUserList(endpoint string, token string) ([]string, error) {
	req, err := http.NewRequest("GET", endpoint+"/admin/realms/master/users", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{}
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

	var userRepresenations []userRepresentation
	err = json.Unmarshal(body, &userRepresenations)
	if err != nil {
		return nil, backoff.Permanent(err)
	}

	userList := make([]string, len(userRepresenations))
	for _, user := range userRepresenations {
		if user.Enabled {
			userList = append(userList, user.ID)
		}
	}
	return userList, nil
}

type applicationListResponse struct {
	Applications []policy `json:"applications"`
}

type policyListResponse struct {
	Policies []simplepolicy `json:"policies"`
}

func getApplicationPolicies(endpoint string, token string) ([]policy, error) {
	req, err := http.NewRequest("GET", endpoint+"/applications/", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{}
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
