# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, IScanIssue
from java.util import ArrayList  # استيراد ArrayList
from jarray import array  # استيراد array من jarray
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Y Scanner")
        
        # تسجيل Listener للاستماع إلى جميع الطلبات والاستجابات
        self._callbacks.registerHttpListener(self)
        
        print("Ahmex000 Scanner loaded!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # نريد فقط تحليل الاستجابات (Responses) وليس الطلبات (Requests)
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response is None:
                return

            responseInfo = self._helpers.analyzeResponse(response)
            headers = responseInfo.getHeaders()
            body = self._helpers.bytesToString(response[responseInfo.getBodyOffset():])

            issues = []

            for keyword, severity in KEYWORDS.items():
                # إذا كانت الكلمة تحتوي على أحرف خاصة (مثل [، {، إلخ)، تعامل معها كـ Regex
                if any(char in keyword for char in ["[", "{", "(", "|", "?", "*", "+", "^", "$"]):
                    pattern = re.compile(keyword, re.IGNORECASE)
                else:
                    # إذا كانت الكلمة عادية، استخدم re.escape للهروب من الأحرف الخاصة
                    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                
                for match in pattern.finditer(body):
                    start, end = match.span()
                    # إنشاء مصفوفة من الأعداد الصحيحة باستخدام jarray
                    markers_array = array([start, end], 'i')  # 'i' تعني مصفوفة من الأعداد الصحيحة
                    # تمرير المصفوفة مباشرة إلى applyMarkers
                    markers = self._callbacks.applyMarkers(messageInfo, None, [markers_array])
                    issues.append(CustomScanIssue(
                        messageInfo.getHttpService(),
                        self._helpers.analyzeRequest(messageInfo).getUrl(),
                        [markers],
                        "Sensitive Keyword Found: {0}".format(keyword),
                        "A sensitive keyword '{0}' was found in the response body.".format(keyword),
                        severity
                    ))

            if issues:
                for issue in issues:
                    self._callbacks.addScanIssue(issue)


KEYWORDS = {
    # General Secrets
    r"affirm[-_]?private": "High",
    r"private[-_]?token": "High",
    r"auth[-_]?token[-_]?key": "High",
    r"system[-_]?password": "High",
    r"api[-_]?key[-_]?secret": "High",
    r"root[-_]?password": "High",
    r"linode[-_]?api[-_]?key": "High",
    r"vultr[-_]?api[-_]?key": "High",
    r"rackspace[-_]?api[-_]?key": "High",
    r"digitalocean[-_]?secret[-_]?key": "High",
    r"firebase[-_]?private[-_]?key": "High",
    r"gcs[-_]?service[-_]?account[-_]?key": "High",
    r"aws[-_]?security[-_]?token": "High",
    r"circleci[-_]?api[-_]?key": "High",
    r"jenkins[-_]?secret[-_]?key": "High",
    r"travisci[-_]?api[-_]?secret": "High",
    r"teamcity[-_]?token": "High",
    r"tumblr[-_]?oauth[-_]?token": "High",
    r"reddit[-_]?api[-_]?key": "High",
    r"pinterest[-_]?app[-_]?secret": "High",
    r"snap[-_]?api[-_]?key": "High",
    r"acme[-_]?private[-_]?key": "High",
    r"ssl[-_]?private[-_]?key": "High",
    r"vpn[-_]?api[-_]?token": "High",
    r"secret[-_]?token[-_][a-zA-Z0-9_]{32}": "High",
    r"password=[a-zA-Z0-9!@#\$%\^&\*\(\)_\+-=]{8,}": "High",
    r"client[-_]?secret=[a-zA-Z0-9_]{64}": "High",
    r"api[-_]?key=[a-zA-Z0-9_-]{40}": "High",

    # Payment Gateway Keys
    r"sk[-_]?live": "High",  # Stripe Live Secret Key
    r"pk[-_]?live": "Medium",  # Stripe Live Public Key
    r"stripe_api_key": "High",  # Stripe API Key
    r"sk_[live|test]_[0-9a-zA-Z]{24}": "High",  # Stripe API Key
    r"Stripe[_-]?Live[_-]?Token": "High",  # Stripe Live Token
    "stripeAccountId": "Medium",
    r"paypal[-_]?client[-_]?secret": "High",  # PayPal Client Secret
    r"square[-_]?access[-_]?token": "High",  # Square Access Token

    # Cloud Provider Secrets
    r"aws[-_]?access[-_]?key[-_]?id": "High",  # aws_access_key_id
    r"aws[-_]?secret[-_]?access[-_]?key": "High",  # aws_secret_access_key
    r"aws[-_]?session[-_]?token": "High",  # aws_session_token
    r"gcp[-_]?service[-_]?account[-_]?key": "High",  # gcp_service_account_key
    r"secret[-_]?key|secretKey": "High",  # secret_key or secretKey
    r"azure[-_]?storage[-_]?account[-_]?key": "High",  # azure_storage_account_key
    r"digitalocean[-_]?token": "High",  # digitalocean_token
    r"heroku[-_]?api[-_]?key": "High",  # heroku_api_key

    # Database Credentials
    r"db[-_]?password": "High",  # db_password
    r"database[-_]?url": "High",  # database_url
    r"mongodb[-_]?uri": "High",  # mongodb_uri
    r"postgresql[-_]?url": "High",  # postgresql_url
    r"mysql[-_]?password": "High",  # mysql_password

    # Social Media Tokens
    r"facebook[-_]?access[-_]?token": "High",  # facebook_access_token
    r"twitter[-_]?api[-_]?key": "High",  # twitter_api_key
    r"instagram[-_]?access[-_]?token": "High",  # instagram_access_token
    r"linkedin[-_]?api[-_]?key": "High",  # linkedin_api_key

    # Version Control Tokens
    r"github[-_]?token": "High",  # github_token
    r"gitlab[-_]?token": "High",  # gitlab_token
    r"bitbucket[-_]?token": "High",  # bitbucket_token

    # CI/CD Secrets
    r"circleci[-_]?token": "High",  # circleci_token
    r"travisci[-_]?token": "High",  # travisci_token
    r"jenkins[-_]?token": "High",  # jenkins_token

    # Messaging Services
    r"slack[-_]?api[-_]?token": "High",  # slack_api_token
    r"slack[-_]?webhook[-_]?url": "High",  # slack_webhook_url
    r"twilio[-_]?auth[-_]?token": "High",  # twilio_auth_token
    r"sendgrid[-_]?api[-_]?key": "High",  # sendgrid_api_key

    # Other Common Secrets
    r"encryption[-_]?key": "High",  # encryption_key
    r"private[-_]?key": "High",  # private_key
    r"public[-_]?key": "High",  # public_key
    r"ssh[-_]?key": "High",  # ssh_key
    r"pgp[-_]?key": "High",  # pgp_key
    r"rsa[-_]?key": "High",  # rsa_key
    r"ssl[-_]?certificate": "High",  # ssl_certificate
    r"jwt[-_]?secret": "High",  # jwt_secret
    r"session[-_]?secret": "High",  # session_secret

    # Regex Patterns for Common Secrets
    r"SG\.[a-zA-Z0-9_]{22}\.[a-zA-Z0-9_-]{43}": "High",  # SendGrid API Key
    r"EAACEdEose0cBA[0-9A-Za-z]+": "High",  # Facebook Access Token
    r"ya29\.[0-9A-Za-z\\-_]+": "High",  # Google OAuth Access Token
    r"AIza[0-9A-Za-z\\-_]{35}": "High",  # Google API Key
    r"shppa_[0-9a-fA-F]{32}": "High",  # Shopify Private App Access Token
    r"ghs_[0-9a-zA-Z]{36}": "High",  # GitHub Server-to-Server Token
    r"glpat-[0-9a-zA-Z\\-_]{20}": "High",  # GitLab Personal Access Token
    r"sq0atp-[0-9A-Za-z\\-_]{22}": "High",  # Square Access Token
    r"sq0csp-[0-9A-Za-z\\-_]{43}": "High",  # Square OAuth Secret
    r"dp\.prod\.[0-9a-zA-Z\\-_]{64}": "High",  # Datadog API Key
    r"r1_[0-9a-zA-Z]{32}": "High",  # Rollbar Access Token
    r"sentry_dsn=[0-9a-zA-Z]{32}": "High",  # Sentry DSN
    r"oauth2-[0-9a-zA-Z]{32}": "High",  # OAuth 2.0 Token
    r"slack_api_token=[0-9a-zA-Z]{24}": "High",  # Slack API Token
    r"heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    r"pagerduty_token=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Token
    r"circleci_token=[0-9a-zA-Z]{40}": "High",  # CircleCI Token
    r"github_token=[0-9a-zA-Z]{40}": "High",  # GitHub Token
    r"bitbucket_token=[0-9a-zA-Z]{40}": "High",  # Bitbucket Token
    r"digitalocean_token=[0-9a-zA-Z]{64}": "High",  # DigitalOcean Token
    r"gcp_service_account_key=[0-9a-zA-Z-_]{64}": "High",  # GCP Service Account Key
    r"azure_storage_account_key=[0-9a-zA-Z+/=]{88}": "High",  # Azure Storage Account Key
    r"twilio_auth_token=[0-9a-fA-F]{32}": "High",  # Twilio Auth Token
    r"sendgrid_api_key=[0-9a-zA-Z]{69}": "High",  # SendGrid API Key
    r"mailgun_api_key=[0-9a-zA-Z]{32}": "High",  # Mailgun API Key
    r"github_client_secret=[0-9a-zA-Z]{40}": "High",  # GitHub Client Secret
    r"facebook_app_secret=[0-9a-zA-Z]{32}": "High",  # Facebook App Secret
    r"twitter_api_secret=[0-9a-zA-Z]{40}": "High",  # Twitter API Secret
    r"google_api_key=[0-9A-Za-z-_]{35}": "High",  # Google API Key
    r"slack_signing_secret=[0-9a-zA-Z]{32}": "High",  # Slack Signing Secret
    r"shopify_api_key=[0-9a-zA-Z]{32}": "High",  # Shopify API Key
    r"dropbox_api_key=[0-9a-zA-Z]{15}": "High",  # Dropbox API Key
    r"box_api_key=[0-9a-zA-Z]{32}": "High",  # Box API Key
    r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}": "High",
    r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com": "Medium",
    r"EAACEdEose0cBA[0-9A-Za-z]+": "High",
    r"asana_access_token=[0-9a-zA-Z]{32}": "High",  # Asana Access Token
    r"trello_api_key=[0-9a-zA-Z]{32}": "High",  # Trello API Key
    r"jira_api_token=[0-9a-zA-Z]{24}": "High",  # Jira API Token
    r"datadog_api_key=[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    r"newrelic_api_key=[0-9a-zA-Z]{40}": "High",  # New Relic API Key
    r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----": "High",  # Covers all private key types
    r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}": "High",
    r"pagerduty_api_key=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Key
    r"api_key[\" :]": "High",  # Covers "api_key", "api_key:", "api_key\""
    r"api_secret": "High",
    r"access_token[\" :]": "High",  # Covers "access_token", "access_token:", "access_token\""
    r"refresh_token[\" :]": "High",  # Covers "refresh_token", "refresh_token:", "refresh_token\""
    r"oauth_token": "High",
    r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+": "High",  # JWT Token
    r"Bearer [a-zA-Z0-9_-]{64}": "High",  # Bearer Token
    r"oauth_token=\"[a-zA-Z0-9_-]{64}\"": "High",  # OAuth Token
    r"client_secret=\"[a-zA-Z0-9_-]{40}\"": "High",  # Client Secret
    r"postgres://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+": "High",  # PostgreSQL URL
    r"mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+": "High",  # MySQL URL
    r"mongodb://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+": "High",  # MongoDB URL
    r"AWS_ACCESS_KEY_ID=\"[A-Z0-9]{20}\"": "High",  # AWS Access Key ID
    r"AWS_SECRET_ACCESS_KEY=\"[a-zA-Z0-9/+]{40}\"": "High",  # AWS Secret Access Key
    r"AZURE_STORAGE_KEY=\"[a-zA-Z0-9/+]{88}\"": "High",  # Azure Storage Key
    r"facebook_access_token=\"[a-zA-Z0-9_-]{128}\"": "High",  # Facebook Access Token
    r"instagram_access_token=\"[a-zA-Z0-9_-]{128}\"": "High",  # Instagram Access Token
    r"square_access_token=\"sq0atp-[a-zA-Z0-9_-]{22}\"": "High",  # Square Access Token
    r"encryption_key=\"[a-zA-Z0-9_-]{64}\"": "High",  # Encryption Key
    r"private_key=\"-----BEGIN RSA PRIVATE KEY-----\"": "High",  # Private Key
    r"password=\"[a-zA-Z0-9_-]{8,}\"": "High",  # Password
    r"secret=\"[a-zA-Z0-9_-]{32}\"": "High",  # Secret
    r"auth=\"[a-zA-Z0-9_-]{64}\"": "High",  # Auth
    r"bearer_token": "High",  # Bearer Token
    r"client_secret": "High",  # Client Secret
    r"session_token": "High",  # Session Token
    r"jwt_token": "High",  # JWT Token
    r"ibm_cloud_api_key": "High",  # IBM Cloud API Key
    r"oracle_cloud_api_key": "High",  # Oracle Cloud API Key
    r"alibaba_cloud_access_key": "High",  # Alibaba Cloud Access Key
    r"redis_password": "High",  # Redis Password
    r"cassandra_password": "High",  # Cassandra Password
    r"elasticsearch_password": "High",  # Elasticsearch Password
    r"braintree_private_key": "High",  # Braintree Private Key
    r"adyen_api_key": "High",  # Adyen API Key
    r"authorize_net_api_key": "High",  # Authorize.net API Key
    r"worldpay_api_key": "High",  # Worldpay API Key
    r"pinterest_access_token": "High",  # Pinterest Access Token
    r"tiktok_access_token": "High",  # TikTok Access Token
    r"snapchat_access_token": "High",  # Snapchat Access Token
    r"svn_password": "High",  # SVN Password
    r"mercurial_token": "High",  # Mercurial Token
    r"gitlab_ci_token": "High",  # GitLab CI Token
    r"azure_devops_token": "High",  # Azure DevOps Token
    r"bamboo_token": "High",  # Bamboo Token
    r"mailgun_api_key": "High",  # Mailgun API Key
    r"amazon_ses_key": "High",  # Amazon SES Key
    r"nexmo_api_key": "High",  # Nexmo API Key
    r"messagebird_api_key": "High",  # MessageBird API Key
    r"datadog_api_key": "High",  # Datadog API Key
    r"newrelic_api_key": "High",  # New Relic API Key
    r"splunk_token": "High",  # Splunk Token
    r"loggly_token": "High",  # Loggly Token
    r"papertrail_token": "High",  # Papertrail Token
    r"grafana_api_key": "High",  # Grafana API Key
    r"terraform_api_key": "High",  # Terraform API Key
    r"google_pay_api_key": "High",  # Google Pay API Key
    r"apple_pay_merchant_id": "High",  # Apple Pay Merchant ID
    r"wechat_pay_api_key": "High",  # WeChat Pay API Key
    r"alipay_api_key": "High",  # Alipay API Key
    r"klarna_api_key": "High",  # Klarna API Key
    r"paddle_api_key": "High",  # Paddle API Key
    r"2checkout_api_key": "High",  # 2Checkout API Key
    r"bluesnap_api_key": "High",  # Bluesnap API Key
    r"froalaEditorActivationKey": "High",  # Froala Editor Activation Key
    r"payu_api_key": "High",  # PayU API Key
    r"mollie_api_key": "High",  # Mollie API Key
    r"skrill_api_key": "High",  # Skrill API Key
    r"payoneer_api_key": "High",  # Payoneer API Key
    r"transferwise_api_key": "High",  # TransferWise API Key
    r"venmo_api_key": "High",  # Venmo API Key
    r"pulumi_api_key": "High",  # Pulumi API Key
    r"ansible_vault_password": "High",  # Ansible Vault Password
    r"chef_server_key": "High",  # Chef Server Key
    r"puppet_master_key": "High",  # Puppet Master Key
    r"kubernetes_secret": "High",  # Kubernetes Secret
    r"docker_registry_password": "High",  # Docker Registry Password
    r"helm_repository_password": "High",  # Helm Repository Password
    r"rancher_api_key": "High",  # Rancher API Key
    r"vault_token": "High",  # Vault Token
    r"hashicorp_vault_key": "High",  # Hashicorp Vault Key
    r"sonarqube_token": "High",  # SonarQube Token
    r"snyk_api_key": "High",  # Snyk API Key
    r"nessus_api_key": "High",  # Nessus API Key
    r"affirm[-_]?Public": "High",  # Affirm Public
    r"internal_api_key": "High",  # Internal API Key
    r"production_db_password": "High",  # Production DB Password
    r"staging_api_key": "High",  # Staging API Key
    r"development_secret": "High",  # Development Secret
    r"test_token": "High",  # Test Token
    r"pagerduty_api_key=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Key
    r"access_token=\"[^\"]+\"": "High",  # Access Token
    r"client_secret=\"[^\"]+\"": "High",  # Client Secret
    r"\"access_token\":\"[^\"]+\"": "High",  # JSON Access Token
    r"\"client_secret\":\"[^\"]+\"": "High",  # JSON Client Secret
    r"key-[0-9a-zA-Z]{32}": "High",  # Mailgun API Key
    r"amzn\.mws\.[0-9a-zA-Z._%+-]{30,50}": "High",  # Amazon MWS Auth Token
    r"dpk_live_[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    r"ABTasty[_-]?API[_-]?Key": "High",  # ABTasty API Key
    r"Algolia[_-]?API[_-]?key": "High",  # Algolia API Key
    r"Amplitude[_-]?API[_-]?Keys": "High",  # Amplitude API Keys
    r"Asana[_-]?Access[_-]?token": "High",  # Asana Access Token
    r"AWS[_-]?Access[_-]?Key[_-]?ID": "High",  # AWS Access Key ID
    r"AWS[_-]?Secret[_-]?Access[_-]?Key": "High",  # AWS Secret Access Key
    r"Azure[_-]?Application[_-]?Insights[_-]?APP[_-]?ID": "High",  # Azure Application Insights APP ID
    r"Azure[_-]?Application[_-]?Insights[_-]?API[_-]?Key": "High",  # Azure Application Insights API Key
    r"Bazaarvoice[_-]?Passkey": "High",  # Bazaarvoice Passkey
    r"Bing[_-]?Maps[_-]?API[_-]?Key": "High",  # Bing Maps API Key
    r"Bit\.ly[_-]?Access[_-]?token": "High",  # Bit.ly Access Token
    r"Branch\.io[_-]?Key": "High",  # Branch.io Key
    r"Branch\.io[_-]?Secret": "High",  # Branch.io Secret
    r"BrowserStack[_-]?Access[_-]?Key": "High",  # BrowserStack Access Key
    r"Buildkite[_-]?Access[_-]?token": "High",  # Buildkite Access Token
    r"ButterCMS[_-]?API[_-]?Key": "High",  # ButterCMS API Key
    r"Calendly[_-]?API[_-]?Key": "High",  # Calendly API Key
    r"Contentful[_-]?Access[_-]?Token": "High",  # Contentful Access Token
    r"CircleCI[_-]?Access[_-]?Token": "High",  # CircleCI Access Token
    r"Cloudflare[_-]?API[_-]?key": "High",  # Cloudflare API Key
    r"Cypress[_-]?record[_-]?key": "High",  # Cypress Record Key
    r"DataDog[_-]?API[_-]?key": "High",  # Datadog API Key
    r"Delighted[_-]?API[_-]?key": "High",  # Delighted API Key
    r"Deviant[_-]?Art[_-]?Access[_-]?Token": "High",  # Deviant Art Access Token
    r"Deviant[_-]?Art[_-]?Secret": "High",  # Deviant Art Secret
    r"Dropbox[_-]?API": "High",  # Dropbox API
    r"Facebook[_-]?Access[_-]?Token": "High",  # Facebook Access Token
    r"Facebook[_-]?AppSecret": "High",  # Facebook App Secret
    r"Firebase[_-]?API[_-]?Key": "High",  # Firebase API Key
    r"Firebase[_-]?Cloud[_-]?Messaging[_-]?\(FCM\)": "High",  # Firebase Cloud Messaging (FCM)
    r"FreshDesk[_-]?API[_-]?Key": "High",  # FreshDesk API Key
    r"Github[_-]?client[_-]?id": "High",  # Github Client ID
    r"Github[_-]?client[_-]?secret": "High",  # Github Client Secret
    r"GitHub[_-]?private[_-]?SSH[_-]?key": "High",  # GitHub Private SSH Key
    r"Github[_-]?Token": "High",  # Github Token
    r"Gitlab[_-]?personal[_-]?access[_-]?token": "High",  # Gitlab Personal Access Token
    r"GitLab[_-]?runner[_-]?registration[_-]?token": "High",  # GitLab Runner Registration Token
    r"Google[_-]?Cloud[_-]?Service[_-]?Account[_-]?credentials": "High",  # Google Cloud Service Account Credentials
    r"Google[_-]?Maps[_-]?API[_-]?key": "High",  # Google Maps API Key
    r"Google[_-]?Recaptcha[_-]?key": "High",  # Google Recaptcha Key
    r"Grafana[_-]?Access[_-]?Token": "High",  # Grafana Access Token
    r"Help[_-]?Scout[_-]?OAUTH": "High",  # Help Scout OAUTH
    r"Heroku[_-]?API[_-]?key": "High",  # Heroku API Key
    r"HubSpot[_-]?API[_-]?key": "High",  # HubSpot API Key
    r"Infura[_-]?API[_-]?key": "High",  # Infura API Key
    r"Instagram[_-]?Access[_-]?Token": "High",  # Instagram Access Token
    r"Instagram[_-]?Basic[_-]?Display[_-]?API": "High",  # Instagram Basic Display API
    r"Instagram[_-]?Graph[_-]?API": "High",  # Instagram Graph API
    r"Ipstack[_-]?API[_-]?Key": "High",  # Ipstack API Key
    r"Iterable[_-]?API[_-]?Key": "High",  # Iterable API Key
    r"JumpCloud[_-]?API[_-]?Key": "High",  # JumpCloud API Key
    r"Keen\.io[_-]?API[_-]?Key": "High",  # Keen.io API Key
    r"LinkedIn[_-]?OAUTH": "High",  # LinkedIn OAUTH
    r"Lokalise[_-]?API[_-]?Key": "High",  # Lokalise API Key
    r"Loqate[_-]?API[_-]?Key": "High",  # Loqate API Key
    r"MailChimp[_-]?API[_-]?Key": "High",  # MailChimp API Key
    r"MailGun[_-]?Private[_-]?Key": "High",  # MailGun Private Key
    r"Mapbox[_-]?API[_-]?key": "High",  # Mapbox API Key
    r"Microsoft[_-]?Azure[_-]?Tenant": "High",  # Microsoft Azure Tenant
    r"Microsoft[_-]?Shared[_-]?Access[_-]?Signatures[_-]?\(SAS\)": "High",  # Microsoft Shared Access Signatures (SAS)
    r"Microsoft[_-]?Teams[_-]?Webhook": "High",  # Microsoft Teams Webhook
    r"New[_-]?Relic[_-]?Personal[_-]?API[_-]?Key[_-]?\(NerdGraph\)": "High",  # New Relic Personal API Key (NerdGraph)
    r"New[_-]?Relic[_-]?REST[_-]?API": "High",  # New Relic REST API
    r"NPM[_-]?token": "High",  # NPM Token
    r"OpsGenie[_-]?API[_-]?Key": "High",  # OpsGenie API Key
    r"Pagerduty[_-]?API[_-]?token": "High",  # Pagerduty API Token
    r"Paypal[_-]?client[_-]?id": "High",  # Paypal Client ID
    r"Paypal[_-]?secret[_-]?key": "High",  # Paypal Secret Key
    r"Pendo[_-]?Integration[_-]?Key": "High",  # Pendo Integration Key
    r"PivotalTracker[_-]?API[_-]?Token": "High",  # PivotalTracker API Token
    r"Razorpay[_-]?API[_-]?key": "High",  # Razorpay API Key
    r"Razorpay[_-]?secret[_-]?key": "High",  # Razorpay Secret Key
    r"Salesforce[_-]?API[_-]?key": "High",  # Salesforce API Key
    r"SauceLabs[_-]?Username": "High",  # SauceLabs Username
    r"SauceLabs[_-]?access[_-]?Key": "High",  # SauceLabs Access Key
    r"SendGrid[_-]?API[_-]?Token": "High",  # SendGrid API Token
    r"Shodan\.io[_-]?API[_-]?Key": "High",  # Shodan.io API Key
    r"Slack[_-]?API[_-]?token": "High",  # Slack API Token
    r"Slack[_-]?Webhook": "High",  # Slack Webhook
    r"Sonarcloud[_-]?API[_-]?Key": "High",  # Sonarcloud API Key
    r"Spotify[_-]?Access[_-]?Token": "High",  # Spotify Access Token
    r"Square[_-]?API[_-]?Key": "High",  # Square API Key
    r"Telegram[_-]?Bot[_-]?API[_-]?Token": "High",  # Telegram Bot API Token
    r"Travis[_-]?CI[_-]?API[_-]?token": "High",  # Travis CI API Token
    r"Twilio[_-]?Account_sid": "High",  # Twilio Account SID
    r"Twilio[_-]?Auth[_-]?token": "High",  # Twilio Auth Token
    r"Twitter[_-]?API[_-]?Secret": "High",  # Twitter API Secret
    r"Twitter[_-]?Bearer[_-]?token": "High",  # Twitter Bearer Token
    r"Visual[_-]?Studio[_-]?App[_-]?Center[_-]?API[_-]?Token": "High",  # Visual Studio App Center API Token
    r"WakaTime[_-]?API[_-]?Key": "High",  # WakaTime API Key
    r"WeGlot[_-]?Api[_-]?Key": "High",  # WeGlot API Key
    r"WPEngine[_-]?API[_-]?Key": "High",  # WPEngine API Key
    r"YouTube[_-]?API[_-]?Key": "High",  # YouTube API Key
    r"Zapier[_-]?Webhook[_-]?Token": "High",  # Zapier Webhook Token
    r"Zendesk[_-]?Access[_-]?token": "High",  # Zendesk Access Token
    r"Zendesk[_-]?API[_-]?key": "High",  # Zendesk API Key
    r"X-Rollbar-Access-Token": "High",  # X-Rollbar Access Token
    r"Access-Token": "High",  # Access Token
    r"AccessToken\"": "High",  # Access Token
    r"(?<=\w|\d|[-_\"':])ProjectConfig(?=\w|\d|[-_\"':=])": "Medium",  # Project Config
    r"addParamsAndAccessTokenToPath": "Medium",  # Add Params and Access Token to Path
    r"api-key :": "High",  # API Key
    r"apiKey": "High",  # API Key
    r"authToken=": "High",  # Auth Token
    r"auth-Token": "High",  # Auth Token
    r"clientSecret": "High",  # Client Secret
    r"checkoutToken": "High",  # Checkout Token
    r"checkout_token": "High",  # Checkout Token
    #r"getBucketedVariation": "Medium",  # Get Bucketed Variation
    r"hideToken": "Medium",  # Hide Token
    r"projectToken": "High",  # Project Token
    r"resolveExperimentBucketMap": "Medium",  # Resolve Experiment Bucket Map
    r"rpctoken": "High",  # RPC Token
    r"showToken": "Medium",  # Show Token
    r"tokenRegex": "Medium",  # Token Regex
    # r"tokenize": "Medium",  # Tokenize
    r"tokenizeNode": "Medium",  # Tokenize Node
    r"visitor_bucketing": "Medium",  # Visitor Bucketing
    r"session_secret": "High",  # Session Secret
    r"azure_ad_token": "High",  # Azure AD Token
    r"google_cloud_token": "High",  # Google Cloud Token
    r"ibm_cloud_token": "High",  # IBM Cloud Token
    r"telegram_bot_token": "High",  # Telegram Bot Token
    r"discord_bot_token": "High",  # Discord Bot Token
    r"whatsapp_api_token": "High",  # WhatsApp API Token
    r"paypal_access_token": "High",  # PayPal Access Token
    r"paypal_secret_key": "High",  # PayPal Secret Key
    r"stripe_connect_token": "High",  # Stripe Connect Token
    r"user_metadata": "Medium",  # User Metadata
    r"app_metadata": "Medium",  # App Metadata
    r"device_metadata": "Medium",  # Device Metadata
    r"analytics_token": "Medium",  # Analytics Token
    r"advertising_id": "Medium",  # Advertising ID
    r"ssh_private_key": "High",  # SSH Private Key
    r"ansible_vault_password": "High",  # Ansible Vault Password
    r"kubernetes_secret": "High",  # Kubernetes Secret
    r"redis_password": "High",  # Redis Password
    r"mongodb_password": "High",  # MongoDB Password
    r"cassandra_password": "High",  # Cassandra Password
    r"local_storage_token": "High",  # Local Storage Token
    # r"session_cookie": "High",  # Session Cookie
    r"local_auth_token": "High",  # Local Auth Token
    r"mobile_app_token": "High",  # Mobile App Token
    r"ios_app_key": "High",  # iOS App Key
    r"android_app_key": "High",  # Android App Key
    r"uber_api_token": "High",  # Uber API Token
    r"lyft_api_token": "High",  # Lyft API Token
    r"delivery_api_token": "High",  # Delivery API Token
    r"weather_api_key": "High",  # Weather API Key
    r"openweathermap_api_key": "High",  # OpenWeatherMap API Key
    r"iam_access_key": "High",  # IAM Access Key
    r"iam_secret_key": "High",  # IAM Secret Key
    r"iam_session_token": "High",  # IAM Session Token
    r"security_event_token": "High",  # Security Event Token
    r"incident_response_token": "High",  # Incident Response Token
    r"bank_api_token": "High",  # Bank API Token
    r"financial_api_key": "High",  # Financial API Key
    r"investment_api_token": "High",  # Investment API Token
    r"lms_api_key": "High",  # LMS API Key
    r"edtech_api_token": "High",  # EdTech API Token
    r"online_learning_token": "High",  # Online Learning Token
    r"health_api_token": "High",  # Health API Token
    r"medical_api_key": "High",  # Medical API Key
    r"patient_data_token": "High",  # Patient Data Token
    r"government_api_key": "High",  # Government API Key
    r"public_service_token": "High",  # Public Service Token
    r"citizen_data_token": "High",  # Citizen Data Token
    r"travel_api_key": "High",  # Travel API Key
    r"hotel_booking_token": "High",  # Hotel Booking Token
    r"flight_booking_token": "High",  # Flight Booking Token
    r"entertainment_api_key": "High",  # Entertainment API Key
    r"streaming_service_token": "High",  # Streaming Service Token
    r"gaming_api_token": "High",  # Gaming API Token
    r"social_media_api_key": "High",  # Social Media API Key
    r"community_api_token": "High",  # Community API Token
    r"chat_api_token": "High",  # Chat API Token
    r"media_api_key": "High",  # Media API Key
    r"news_api_token": "High",  # News API Token
    r"broadcast_api_token": "High",  # Broadcast API Token
    r"real_estate_api_key": "High",  # Real Estate API Key
    r"property_management_token": "High",  # Property Management Token
    r"rental_api_token": "High",  # Rental API Token
    r"logistics_api_key": "High",  # Logistics API Key
    r"shipping_api_token": "High",  # Shipping API Token
    r"supply_chain_token": "High",  # Supply Chain Token
    r"agriculture_api_key": "High",  # Agriculture API Key
    r"farming_api_token": "High",  # Farming API Token
    r"crop_management_token": "High",  # Crop Management Token
    r"environmental_api_key": "High",  # Environmental API Key
    r"sustainability_token": "High",  # Sustainability Token
    r"climate_api_token": "High",  # Climate API Token
    r"legal_api_key": "High",  # Legal API Key
    r"law_enforcement_token": "High",  # Law Enforcement Token
    r"court_api_token": "High",  # Court API Token
    r"military_api_key": "High",  # Military API Key
    r"defense_api_token": "High",  # Defense API Token
    r"security_clearance_token": "High",  # Security Clearance Token
    r"space_api_key": "High",  # Space API Key
    r"satellite_api_token": "High",  # Satellite API Token
    r"astronomy_api_token": "High",  # Astronomy API Token
    r"maritime_api_key": "High",  # Maritime API Key
    r"shipping_api_token": "High",  # Shipping API Token
    r"naval_api_token": "High",  # Naval API Token
    r"aviation_api_key": "High",  # Aviation API Key
    r"airline_api_token": "High",  # Airline API Token
    r"flight_api_token": "High",  # Flight API Token
    r"land_api_key": "High",  # Land API Key
    r"transportation_api_token": "High",  # Transportation API Token
    r"road_api_token": "High",  # Road API Token
    r"water_api_key": "High",  # Water API Key
    r"aquatic_api_token": "High",  # Aquatic API Token
    r"marine_api_token": "High",  # Marine API Token
    r"geology_api_key": "High",  # Geology API Key
    r"earthquake_api_token": "High",  # Earthquake API Token
    r"mining_api_token": "High",  # Mining API Token
    r"astronomy_api_key": "High",  # Astronomy API Key
    r"telescope_api_token": "High",  # Telescope API Token
    r"planet_api_token": "High",  # Planet API Token
    r"biology_api_key": "High",  # Biology API Key
    r"genetics_api_token": "High",  # Genetics API Token
    r"microbiology_api_token": "High",  # Microbiology API Token
    r"chemistry_api_key": "High",  # Chemistry API Key
    r"chemical_api_token": "High",  # Chemical API Token
    r"lab_api_token": "High",  # Lab API Token
    r"physics_api_key": "High",  # Physics API Key
    r"quantum_api_token": "High",  # Quantum API Token
    r"energy_api_token": "High",  # Energy API Token
    r"sports_api_key": "High",  # Sports API Key
    r"fitness_api_token": "High",  # Fitness API Token
    r"athlete_api_token": "High",  # Athlete API Token
    r"art_api_key": "High",  # Art API Key
    r"music_api_token": "High",  # Music API Token
    r"painting_api_token": "High",  # Painting API Token
    r"literature_api_key": "High",  # Literature API Key
    r"poetry_api_token": "High",  # Poetry API Token
    r"novel_api_token": "High",  # Novel API Token
    r"history_api_key": "High",  # History API Key
    r"archaeology_api_token": "High",  # Archaeology API Token
    r"museum_api_token": "High",  # Museum API Token
    r"geography_api_key": "High",  # Geography API Key
    r"map_api_token": "High",  # Map API Token
    r"location_api_token": "High",  # Location API Token
    r"politics_api_key": "High",  # Politics API Key
    r"government_api_token": "High",  # Government API Token
    r"election_api_token": "High",  # Election API Token
    r"economics_api_key": "High",  # Economics API Key
    r"finance_api_token": "High",  # Finance API Token
    r"market_api_token": "High",  # Market API Token
    r"social_api_key": "High",  # Social API Key
    r"community_api_token": "High",  # Community API Token
    r"network_api_token": "High",  # Network API Token
    r"culture_api_key": "High",  # Culture API Key
    r"heritage_api_token": "High",  # Heritage API Token
    r"tradition_api_token": "High",  # Tradition API Token
    r"religion_api_key": "High",  # Religion API Key
    r"faith_api_token": "High",  # Faith API Token
    r"spirituality_api_token": "High",  # Spirituality API Token
    r"philosophy_api_key": "High",  # Philosophy API Key
    r"thought_api_token": "High",  # Thought API Token
    r"wisdom_api_token": "High",  # Wisdom API Token
    r"psychology_api_key": "High",  # Psychology API Key
    r"mind_api_token": "High",  # Mind API Token
    r"braze[-_]?(key|api[-_]?key|token)": "Medium",
    r"braze[-_]?(private[-_]?key|key|api[-_]?key|token)": "Medium",
    r"behavior_api_token": "High",  # Behavior API Token
    r".sql": "High",  # SQL Files
    r".pptx": "High",  # PPTX Files
    r".tar.gz": "High",  # TAR.GZ Files
    r".tgz": "High",  # TGZ Files
    r".bak": "High",  # BAK Files
   '''
    r".xls": "High",  # XLS Files
    r".xml": "High",  # XML Files
    r".xlsx": "High",  # XLSX Files
    r".json": "High",  # JSON Files
    r".pdf": "High",  # PDF Files
    r".doc": "High",  # DOC Files
    r".docx": "High",  # DOCX Files
    r".rar": "High",  # RAR Files
    r".7z": "High",  # 7Z Files
    r".txt": "High",  # TXT Files
    r".zip": "High",  # ZIP Files
    '''
     r"\.txt$": "Low",
    r"\.log$": "Low",
    r"\.cache$": "Low",
    r"\.secret$": "High",
    r"\.db$": "High",
    r"\.backup$": "High",
    r"\.yml$": "Medium",
    r"\.json$": "Medium",
    r"\.gz$": "Medium",
    r"\.rar$": "Medium",
    r"\.zip$": "Medium",
    r"\.tar$": "Medium",
    r"\.sql$": "High",
    r"\.env$": "High",
    r"\.config$": "Medium",
    r"\.conf$": "Medium",
    r"\.ini$": "Medium",
    r"\.htaccess$": "High",
    r"\.htpasswd$": "High",
    r"\.pem$": "High",
    r"\.key$": "High",
    r"\.crt$": "High",
    r"\.cer$": "High",
    r"\.pfx$": "High",
    r"\.p12$": "High",
    r"\.swp$": "Low",
    r"\.bak$": "Medium",
    r"\.old$": "Medium",
    r"\.tmp$": "Low",
    r"\.temp$": "Low",
    r"\.dump$": "High",
    r"\.passwd$": "High",
    r"\.shadow$": "High",
    r"\.git$": "High",
    r"\.svn$": "High",
    r"\.DS_Store$": "Low",
    r"\.idea$": "Low",
    r"\.vscode$": "Low",
    r"\.bash_history$": "High",
    r"\.zsh_history$": "High"
}
    

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
        


#----------
# ثانيا البحث الصحيح عن بعض الكلمات لتقليل ال FalseP [ "token" => "token\"" , "token\"" ]
#----------

# delete some regex bottern's [ 
#       "xoxb-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Bot Token
#       "xoxp-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack User Token
#       "xoxe-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Legacy Token
#       "xoxs-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack App Token
#
#    // this searches to Slack leaks data due false positive alerts ]
#----------
# deleted "password" key word
#
