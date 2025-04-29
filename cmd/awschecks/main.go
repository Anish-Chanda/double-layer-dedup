package awschecks

import (
	"context"
	"fmt"

	"github.com/Anish-Chanda/double-layer-dedup/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Returns the AWS account ID, or error
func VerifyAWS(ctx context.Context, awsCfg aws.Config) (string, error) {
	stsClient := sts.NewFromConfig(awsCfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return *out.Account, nil
}

func main() {
	cfg, _ := config.Load()
	awsCfg, _ := awsConfig.LoadDefaultConfig(context.Background(),
		awsConfig.WithRegion(cfg.AWSRegion))
	account, err := VerifyAWS(context.Background(), awsCfg)
	if err != nil {
		panic("AWS not configured: " + err.Error())
	}
	fmt.Println("Running under AWS account", account)
}
