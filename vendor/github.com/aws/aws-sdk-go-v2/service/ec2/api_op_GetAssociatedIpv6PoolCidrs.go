// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Gets information about the IPv6 CIDR block associations for a specified IPv6
// address pool.
func (c *Client) GetAssociatedIpv6PoolCidrs(ctx context.Context, params *GetAssociatedIpv6PoolCidrsInput, optFns ...func(*Options)) (*GetAssociatedIpv6PoolCidrsOutput, error) {
	if params == nil {
		params = &GetAssociatedIpv6PoolCidrsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetAssociatedIpv6PoolCidrs", params, optFns, addOperationGetAssociatedIpv6PoolCidrsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetAssociatedIpv6PoolCidrsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetAssociatedIpv6PoolCidrsInput struct {

	// The ID of the IPv6 address pool.
	//
	// This member is required.
	PoolId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun bool

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults int32

	// The token for the next page of results.
	NextToken *string
}

type GetAssociatedIpv6PoolCidrsOutput struct {

	// Information about the IPv6 CIDR block associations.
	Ipv6CidrAssociations []types.Ipv6CidrAssociation

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addOperationGetAssociatedIpv6PoolCidrsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpGetAssociatedIpv6PoolCidrs{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpGetAssociatedIpv6PoolCidrs{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpGetAssociatedIpv6PoolCidrsValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetAssociatedIpv6PoolCidrs(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

// GetAssociatedIpv6PoolCidrsAPIClient is a client that implements the
// GetAssociatedIpv6PoolCidrs operation.
type GetAssociatedIpv6PoolCidrsAPIClient interface {
	GetAssociatedIpv6PoolCidrs(context.Context, *GetAssociatedIpv6PoolCidrsInput, ...func(*Options)) (*GetAssociatedIpv6PoolCidrsOutput, error)
}

var _ GetAssociatedIpv6PoolCidrsAPIClient = (*Client)(nil)

// GetAssociatedIpv6PoolCidrsPaginatorOptions is the paginator options for
// GetAssociatedIpv6PoolCidrs
type GetAssociatedIpv6PoolCidrsPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// GetAssociatedIpv6PoolCidrsPaginator is a paginator for
// GetAssociatedIpv6PoolCidrs
type GetAssociatedIpv6PoolCidrsPaginator struct {
	options   GetAssociatedIpv6PoolCidrsPaginatorOptions
	client    GetAssociatedIpv6PoolCidrsAPIClient
	params    *GetAssociatedIpv6PoolCidrsInput
	nextToken *string
	firstPage bool
}

// NewGetAssociatedIpv6PoolCidrsPaginator returns a new
// GetAssociatedIpv6PoolCidrsPaginator
func NewGetAssociatedIpv6PoolCidrsPaginator(client GetAssociatedIpv6PoolCidrsAPIClient, params *GetAssociatedIpv6PoolCidrsInput, optFns ...func(*GetAssociatedIpv6PoolCidrsPaginatorOptions)) *GetAssociatedIpv6PoolCidrsPaginator {
	if params == nil {
		params = &GetAssociatedIpv6PoolCidrsInput{}
	}

	options := GetAssociatedIpv6PoolCidrsPaginatorOptions{}
	if params.MaxResults != 0 {
		options.Limit = params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &GetAssociatedIpv6PoolCidrsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *GetAssociatedIpv6PoolCidrsPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next GetAssociatedIpv6PoolCidrs page.
func (p *GetAssociatedIpv6PoolCidrsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*GetAssociatedIpv6PoolCidrsOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	params.MaxResults = p.options.Limit

	result, err := p.client.GetAssociatedIpv6PoolCidrs(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken && prevToken != nil && p.nextToken != nil && *prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opGetAssociatedIpv6PoolCidrs(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "GetAssociatedIpv6PoolCidrs",
	}
}
