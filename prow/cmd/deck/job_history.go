/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	prowio "k8s.io/test-infra/pkg/io"
	"k8s.io/test-infra/prow/pod-utils/gcs"
)

const (
	resultsPerPage  = 20
	idParam         = "buildId"
	latestBuildFile = "latest-build.txt"

	// ** Job history assumes the GCS layout specified here:
	// https://github.com/kubernetes/test-infra/tree/master/gubernator#gcs-bucket-layout
	logsPrefix     = gcs.NonPRLogs
	spyglassPrefix = "/view"
	emptyID        = int64(-1) // indicates no build id was specified
)

var (
	linkRe   = regexp.MustCompile("/([0-9]+)\\.txt$")
)

type buildData struct {
	index        int
	jobName      string
	prefix       string
	SpyglassLink string
	ID           string
	Started      time.Time
	Duration     time.Duration
	Result       string
	commitHash   string
}

type jobHistoryTemplate struct {
	OlderLink    string
	NewerLink    string
	LatestLink   string
	Name         string
	ResultsShown int
	ResultsTotal int
	Builds       []buildData
}

func readLatestBuild(opener prowio.Opener, root string) (int64, error) {
	key := prowio.JoinStoragePath(root, latestBuildFile)
	data, err := opener.ReadObject(context.TODO(), key)
	if err != nil {
		return -1, fmt.Errorf("failed to read %s: %v", key, err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return -1, fmt.Errorf("failed to parse %s: %v", key, err)
	}
	return n, nil
}

// resolve sym links into the actual log directory for a particular test run
func resolveSymLink(opener prowio.Opener, symLink string) (string, error) {
	data, err := opener.ReadObject(context.TODO(), symLink)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %v", symLink, err)
	}
	return string(data), nil
}

func spyglassLink(opener prowio.Opener, storagePath, id string) (string, error) {
	p, err := getPath(opener, storagePath, id, "")
	if err != nil {
		return "", fmt.Errorf("failed to get path: %v", err)
	}
	return path.Join(spyglassPrefix, prowio.EncodeStorageURL(p)), nil
}

func getPath(opener prowio.Opener, root, id, fname string) (string, error) {
	_, relativePath, err := prowio.ParseStoragePath(root)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(relativePath, logsPrefix) {
		return path.Join(root, id, fname), nil
	}
	symLink := prowio.JoinStoragePath(root, id+".txt")
	dir, err := resolveSymLink(opener, symLink)
	if err != nil {
		return "", fmt.Errorf("failed to resolve sym link: %v", err)
	}
	return prowio.JoinStoragePath(dir, fname), nil
}

// reads specified JSON file in to `data`
func readJSON(opener prowio.Opener, key string, data interface{}) error {
	rawData, err := opener.ReadObject(context.TODO(), key)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", key, err)
	}
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %v", key, err)
	}
	return nil
}

// Gets all build ids for a job.
func listBuildIDs(opener prowio.Opener, root string) ([]int64, error) {
	ids := []int64{}
	if strings.HasPrefix(root, logsPrefix) {
		dirs, err := opener.ListSubDirs(context.TODO(), root)
		if err != nil {
			return ids, fmt.Errorf("failed to list GCS directories: %v", err)
		}
		for _, dir := range dirs {
			leaf := path.Base(dir)
			i, err := strconv.ParseInt(leaf, 10, 64)
			if err == nil {
				ids = append(ids, i)
			} else {
				logrus.WithField("gcs-path", dir).Warningf("unrecognized directory name (expected int64): %s", leaf)
			}
		}
	} else {
		keys, err := opener.ListSubPaths(context.TODO(), root)
		if err != nil {
			return ids, fmt.Errorf("failed to list GCS keys: %v", err)
		}
		for _, key := range keys {
			matches := linkRe.FindStringSubmatch(key)
			if len(matches) == 2 {
				i, err := strconv.ParseInt(matches[1], 10, 64)
				if err == nil {
					ids = append(ids, i)
				} else {
					logrus.Warningf("unrecognized file name (expected <int64>.txt): %s", key)
				}
			}
		}
	}
	return ids, nil
}

func parseJobHistURL(url *url.URL) (path string, buildID int64, err error) {
	buildID = emptyID
	path = strings.TrimPrefix(url.Path, "/job-history/")
	if path == "" {
		err = fmt.Errorf("missing GCS bucket name: %v", url.Path)
		return
	}
	path = prowio.DecodeStorageURL(path)

	if idVals := url.Query()[idParam]; len(idVals) >= 1 && idVals[0] != "" {
		buildID, err = strconv.ParseInt(idVals[0], 10, 64)
		if err != nil {
			err = fmt.Errorf("invalid value for %s: %v", idParam, err)
			return
		}
		if buildID < 0 {
			err = fmt.Errorf("invalid value %s = %d", idParam, buildID)
			return
		}
	}

	return
}

func linkID(url *url.URL, id int64) string {
	u := *url
	q := u.Query()
	var val string
	if id != emptyID {
		val = strconv.FormatInt(id, 10)
	}
	q.Set(idParam, val)
	u.RawQuery = q.Encode()
	return u.String()
}

func getBuildData(opener prowio.Opener, dir string) (buildData, error) {
	b := buildData{
		Result:     "Unknown",
		commitHash: "Unknown",
	}
	started := gcs.Started{}
	err := readJSON(opener, prowio.JoinStoragePath(dir, "started.json"), &started)
	if err != nil {
		return b, fmt.Errorf("failed to read started.json: %v", err)
	}
	b.Started = time.Unix(started.Timestamp, 0)
	if commitHash, err := getPullCommitHash(started.Pull); err == nil {
		b.commitHash = commitHash
	}
	finished := gcs.Finished{}
	err = readJSON(opener, prowio.JoinStoragePath(dir, "finished.json"), &finished)
	if err != nil {
		b.Result = "Pending"
		logrus.Debugf("failed to read finished.json (job might be unfinished): %v", err)
	}
	if finished.Revision != "" {
		b.commitHash = finished.Revision
	}
	if finished.Timestamp != nil {
		b.Duration = time.Unix(*finished.Timestamp, 0).Sub(b.Started)
	} else {
		b.Duration = time.Now().Sub(b.Started).Round(time.Second)
	}
	if finished.Result != "" {
		b.Result = finished.Result
	}
	return b, nil
}

// assumes a to be sorted in descending order
// returns a subslice of a along with its indices (inclusive)
func cropResults(a []int64, max int64) ([]int64, int, int) {
	res := []int64{}
	firstIndex := -1
	lastIndex := 0
	for i, v := range a {
		if v <= max {
			res = append(res, v)
			if firstIndex == -1 {
				firstIndex = i
			}
			lastIndex = i
			if len(res) >= resultsPerPage {
				break
			}
		}
	}
	return res, firstIndex, lastIndex
}

// golang <3
type int64slice []int64

func (a int64slice) Len() int           { return len(a) }
func (a int64slice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a int64slice) Less(i, j int) bool { return a[i] < a[j] }

// Gets job history from the GCS bucket specified in config.
func getJobHistory(url *url.URL, opener prowio.Opener) (jobHistoryTemplate, error) {
	start := time.Now()
	tmpl := jobHistoryTemplate{}

	storagePath, top, err := parseJobHistURL(url)
	if err != nil {
		return tmpl, fmt.Errorf("invalid url %s: %v", url.String(), err)
	}
	tmpl.Name = storagePath

	latest, err := readLatestBuild(opener, storagePath)
	if err != nil {
		return tmpl, fmt.Errorf("failed to locate build data: %v", err)
	}
	if top == emptyID || top > latest {
		top = latest
	}
	if top != latest {
		tmpl.LatestLink = linkID(url, emptyID)
	}

	buildIDs, err := listBuildIDs(opener, storagePath)
	if err != nil {
		return tmpl, fmt.Errorf("failed to get build ids: %v", err)
	}
	sort.Sort(sort.Reverse(int64slice(buildIDs)))

	// determine which results to display on this page
	shownIDs, firstIndex, lastIndex := cropResults(buildIDs, top)

	// get links to the neighboring pages
	if firstIndex > 0 {
		nextIndex := firstIndex - resultsPerPage
		// here emptyID indicates the most recent build, which will not necessarily be buildIDs[0]
		next := emptyID
		if nextIndex >= 0 {
			next = buildIDs[nextIndex]
		}
		tmpl.NewerLink = linkID(url, next)
	}
	if lastIndex < len(buildIDs)-1 {
		tmpl.OlderLink = linkID(url, buildIDs[lastIndex+1])
	}

	tmpl.Builds = make([]buildData, len(shownIDs))
	tmpl.ResultsShown = len(shownIDs)
	tmpl.ResultsTotal = len(buildIDs)

	// concurrently fetch data for all of the builds to be shown
	bch := make(chan buildData)
	for i, buildID := range shownIDs {
		go func(i int, buildID int64) {
			id := strconv.FormatInt(buildID, 10)
			dir, err := getPath(opener, storagePath, id, "")
			if err != nil {
				logrus.Errorf("failed to get path: %v", err)
				bch <- buildData{}
				return
			}
			b, err := getBuildData(opener, dir)
			if err != nil {
				logrus.Warningf("build %d information incomplete: %v", buildID, err)
			}
			b.index = i
			b.ID = id
			b.SpyglassLink, err = spyglassLink(opener, storagePath, id)
			if err != nil {
				logrus.Errorf("failed to get spyglass link: %v", err)
			}
			bch <- b
		}(i, buildID)
	}
	for i := 0; i < len(shownIDs); i++ {
		b := <-bch
		tmpl.Builds[b.index] = b
	}

	elapsed := time.Now().Sub(start)
	logrus.Infof("loaded %s in %v", url.Path, elapsed)
	return tmpl, nil
}
