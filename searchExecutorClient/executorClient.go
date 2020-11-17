package searchExecutorClient

import (
	"context"
	"errors"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	"time"
)

const (
	SearchExecutorServiceBasePath = "v2/search"
	maxElasticResults             = 10000
)

// SearchExecutorClient implements an http client for communication with an e3db Search Executor service.
// currently this client only grabs meta information from e
type SearchExecutorClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
}

// Search makes a search request to executor and returns the parsed response
// this method does not do the work of decrypting the data associated.
func (c *SearchExecutorClient) Search(ctx context.Context, params ExecutorQueryRequest) (*ExecutorQueryResponse, error) {
	var result *ExecutorQueryResponse
	path := c.Host + "/v2/search"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// New returns searchExectorCient from generic config.
func New(config e3dbClients.ClientConfig) SearchExecutorClient {
	authService := authClient.New(config)
	return SearchExecutorClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
	}
}

// TimePaginateSearch paginates through search params paginating every ExecutorQueryRequest.Limit result and
// downselecting by time if total results are greater than the maximum search size (10,000).
func TimePaginateSearch(searchClient SearchExecutorClient, searchParams ExecutorQueryRequest) (*[]pdsClient.ListedRecord, int64, error) {
	if !searchParams.Range.Before.After(searchParams.Range.After) {
		return nil, 0, errors.New("Range start and end time must be valid")
	}
	var allResults []pdsClient.ListedRecord
	ctx := context.Background()
	var totalResults int64

	for { // paginate
		searchResults, err := searchClient.Search(ctx, searchParams)
		if err != nil {
			return &allResults, totalResults, err
		}
		if searchResults.TotalResults >= maxElasticResults {
			beginTime := searchParams.Range.After
			endTime := searchParams.Range.Before

			midTime := time.Unix((beginTime.Unix()+endTime.Unix())/2, 0)

			// left
			leftQuery := searchParams
			leftQuery.Range.After = beginTime
			leftQuery.Range.Before = midTime
			leftResults, leftTotal, err := TimePaginateSearch(searchClient, leftQuery)
			if err != nil {
				return nil, 0, err
			}

			allResults = append(allResults, *leftResults...)
			totalResults += leftTotal

			// right
			rightQuery := searchParams
			rightQuery.Range.After = midTime
			rightQuery.Range.Before = endTime

			rightResults, rightTotal, err := TimePaginateSearch(searchClient, rightQuery)
			if err != nil {
				return nil, 0, err
			}

			allResults = append(allResults, *rightResults...)
			totalResults += rightTotal
			return &allResults, totalResults, err
		}
		allResults = append(allResults, searchResults.ResultList...)
		totalResults += int64(len(searchResults.ResultList))
		if searchResults.LastIndex == 0 {
			break
		}
		searchParams.NextToken = searchResults.LastIndex
	}
	return &allResults, totalResults, nil
}
