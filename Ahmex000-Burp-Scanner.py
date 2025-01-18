# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, IScanIssue
from java.util import ArrayList  # استيراد ArrayList
from jarray import array  # استيراد array من jarray
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Auto Sensitive Keyword Scanner")
        
        # تسجيل Listener للاستماع إلى جميع الطلبات والاستجابات
        self._callbacks.registerHttpListener(self)
        
        print("Auto Sensitive Keyword Scanner loaded!")

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
    "affirm": "Medium",
    "affirm_private": "High",
    "api_key": "High",
    "secret": "High",
    "private": "Medium",
    "token": "Medium",

    # Payment Gateway Keys
    "sk_live": "High",  # Stripe Live Secret Key
    "pk_live": "Medium",  # Stripe Live Public Key
    "paypal_client_secret": "High",  # PayPal Client Secret
    "square_access_token": "High",  # Square Access Token

    # Cloud Provider Secrets
    "aws_access_key_id": "High",
    "aws_secret_access_key": "High",
    "aws_session_token": "High",
    "gcp_service_account_key": "High",
    "azure_storage_account_key": "High",
    "digitalocean_token": "High",
    "heroku_api_key": "High",

    # Database Credentials
    "db_password": "High",
    "database_url": "High",
    "mongodb_uri": "High",
    "postgresql_url": "High",
    "mysql_password": "High",

    # Social Media Tokens
    "facebook_access_token": "High",
    "twitter_api_key": "High",
    "instagram_access_token": "High",
    "linkedin_api_key": "High",

    # Version Control Tokens
    "github_token": "High",
    "gitlab_token": "High",
    "bitbucket_token": "High",

    # CI/CD Secrets
    "circleci_token": "High",
    "travisci_token": "High",
    "jenkins_token": "High",

    # Messaging Services
    "slack_api_token": "High",
    "slack_webhook_url": "High",
    "twilio_auth_token": "High",
    "sendgrid_api_key": "High",

    # Other Common Secrets
    "encryption_key": "High",
    "private_key": "High",
    "public_key": "High",
    "ssh_key": "High",
    "pgp_key": "High",
    "rsa_key": "High",
    "ssl_certificate": "High",
    "jwt_secret": "High",
    "session_secret": "High",

    # Regex Patterns for Common Secrets
    "AKIA[0-9A-Z]{16}": "High",  # AWS Access Key ID
    "SG\\.[a-zA-Z0-9_]{22}\\.[a-zA-Z0-9_-]{43}": "High",  # SendGrid API Key
    "sk_live_[0-9a-zA-Z]{24}": "High",  # Stripe Live Secret Key
    "sk_test_[0-9a-zA-Z]{24}": "High",  # Stripe Test Secret Key
    "EAACEdEose0cBA[0-9A-Za-z]+": "High",  # Facebook Access Token
    "ya29\\.[0-9A-Za-z\\-_]+": "High",  # Google OAuth Access Token
    "AIza[0-9A-Za-z\\-_]{35}": "High",  # Google API Key
    "shppa_[0-9a-fA-F]{32}": "High",  # Shopify Private App Access Token
    "xoxb-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Bot Token
    "xoxp-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack User Token
    "xoxe-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Legacy Token
    "xoxs-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack App Token
    "ghp_[0-9a-zA-Z]{36}": "High",  # GitHub Personal Access Token
    "ghs_[0-9a-zA-Z]{36}": "High",  # GitHub Server-to-Server Token
    "glpat-[0-9a-zA-Z\\-_]{20}": "High",  # GitLab Personal Access Token
    "sq0atp-[0-9A-Za-z\\-_]{22}": "High",  # Square Access Token
    "sq0csp-[0-9A-Za-z\\-_]{43}": "High",  # Square OAuth Secret
    "dp\\.prod\\.[0-9a-zA-Z\\-_]{64}": "High",  # Datadog API Key
    "r1_[0-9a-zA-Z]{32}": "High",  # Rollbar Access Token
    "sentry_dsn=[0-9a-zA-Z]{32}": "High",  # Sentry DSN
    "oauth2-[0-9a-zA-Z]{32}": "High",  # OAuth 2.0 Token
    "slack_api_token=[0-9a-zA-Z]{24}": "High",  # Slack API Token
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_token=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Token
    "circleci_token=[0-9a-zA-Z]{40}": "High",  # CircleCI Token
    "github_token=[0-9a-zA-Z]{40}": "High",  # GitHub Token
    "bitbucket_token=[0-9a-zA-Z]{40}": "High",  # Bitbucket Token
    "digitalocean_token=[0-9a-zA-Z]{64}": "High",  # DigitalOcean Token
    "aws_secret_access_key=[0-9a-zA-Z/+=]{40}": "High",  # AWS Secret Access Key
    "gcp_service_account_key=[0-9a-zA-Z-_]{64}": "High",  # GCP Service Account Key
    "azure_storage_account_key=[0-9a-zA-Z+/=]{88}": "High",  # Azure Storage Account Key
    "twilio_auth_token=[0-9a-fA-F]{32}": "High",  # Twilio Auth Token
    "sendgrid_api_key=[0-9a-zA-Z]{69}": "High",  # SendGrid API Key
    "mailgun_api_key=[0-9a-zA-Z]{32}": "High",  # Mailgun API Key
    "stripe_api_key=[0-9a-zA-Z]{24}": "High",  # Stripe API Key
    "github_client_secret=[0-9a-zA-Z]{40}": "High",  # GitHub Client Secret
    "facebook_app_secret=[0-9a-zA-Z]{32}": "High",  # Facebook App Secret
    "twitter_api_secret=[0-9a-zA-Z]{40}": "High",  # Twitter API Secret
    "google_api_key=[0-9A-Za-z-_]{35}": "High",  # Google API Key
    "slack_signing_secret=[0-9a-zA-Z]{32}": "High",  # Slack Signing Secret
    "shopify_api_key=[0-9a-zA-Z]{32}": "High",  # Shopify API Key
    "paypal_client_secret=[0-9a-zA-Z]{64}": "High",  # PayPal Client Secret
    "dropbox_api_key=[0-9a-zA-Z]{15}": "High",  # Dropbox API Key
    "box_api_key=[0-9a-zA-Z]{32}": "High",  # Box API Key
    "asana_access_token=[0-9a-zA-Z]{32}": "High",  # Asana Access Token
    "trello_api_key=[0-9a-zA-Z]{32}": "High",  # Trello API Key
    "jira_api_token=[0-9a-zA-Z]{24}": "High",  # Jira API Token
    "datadog_api_key=[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    "newrelic_api_key=[0-9a-zA-Z]{40}": "High",  # New Relic API Key
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_api_key=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Key
        "api_key": "High",
    "api_secret": "High",
    "access_token": "High",
    "refresh_token": "High",
    "oauth_token": "High",
    "bearer_token": "High",
    "client_id": "High",
    "client_secret": "High",
    "session_token": "High",
    "jwt_token": "High",
    "encryption_key": "High",
    "private_key": "High",
    "public_key": "High",
    "ssh_key": "High",
    "pgp_key": "High",
    "rsa_key": "High",
    "ssl_certificate": "High",
    "jwt_secret": "High",
    "session_secret": "High",

    # Cloud Provider Secrets
    "aws_access_key_id": "High",
    "aws_secret_access_key": "High",
    "aws_session_token": "High",
    "gcp_service_account_key": "High",
    "azure_storage_account_key": "High",
    "digitalocean_token": "High",
    "heroku_api_key": "High",
    "ibm_cloud_api_key": "High",
    "oracle_cloud_api_key": "High",
    "alibaba_cloud_access_key": "High",

    # Database Credentials
    "db_password": "High",
    "database_url": "High",
    "mongodb_uri": "High",
    "postgresql_url": "High",
    "mysql_password": "High",
    "redis_password": "High",
    "cassandra_password": "High",
    "elasticsearch_password": "High",

    # Payment Gateway Keys
    "stripe_api_key": "High",
    "paypal_client_secret": "High",
    "square_access_token": "High",
    "braintree_private_key": "High",
    "adyen_api_key": "High",
    "authorize_net_api_key": "High",
    "worldpay_api_key": "High",

    # Social Media Tokens
    "facebook_access_token": "High",
    "twitter_api_key": "High",
    "instagram_access_token": "High",
    "linkedin_api_key": "High",
    "pinterest_access_token": "High",
    "tiktok_access_token": "High",
    "snapchat_access_token": "High",

    # Version Control Tokens
    "github_token": "High",
    "gitlab_token": "High",
    "bitbucket_token": "High",
    "svn_password": "High",
    "mercurial_token": "High",

    # CI/CD Secrets
    "circleci_token": "High",
    "travisci_token": "High",
    "jenkins_token": "High",
    "gitlab_ci_token": "High",
    "azure_devops_token": "High",
    "bamboo_token": "High",

    # Messaging Services
    "slack_api_token": "High",
    "slack_webhook_url": "High",
    "twilio_auth_token": "High",
    "sendgrid_api_key": "High",
    "mailgun_api_key": "High",
    "amazon_ses_key": "High",
    "nexmo_api_key": "High",
    "messagebird_api_key": "High",

    # Monitoring and Logging
    "datadog_api_key": "High",
    "newrelic_api_key": "High",
    "splunk_token": "High",
    "loggly_token": "High",
    "papertrail_token": "High",
    "grafana_api_key": "High",

    # Infrastructure as Code
    "terraform_api_key": "High",
    "pulumi_api_key": "High",
    "ansible_vault_password": "High",
    "chef_server_key": "High",
    "puppet_master_key": "High",

    # Container Orchestration
    "kubernetes_secret": "High",
    "docker_registry_password": "High",
    "helm_repository_password": "High",
    "rancher_api_key": "High",

    # Security Tools
    "vault_token": "High",
    "hashicorp_vault_key": "High",
    "sonarqube_token": "High",
    "snyk_api_key": "High",
    "nessus_api_key": "High",

    # Other Common Secrets
    "affirm_private": "High",
    "affirm_public": "High",
    "internal_api_key": "High",
    "production_db_password": "High",
    "staging_api_key": "High",
    "development_secret": "High",
    "test_token": "High",

    # Regex Patterns for Common Secrets
    "AKIA[0-9A-Z]{16}": "High",  # AWS Access Key ID
    "SG\\.[a-zA-Z0-9_]{22}\\.[a-zA-Z0-9_-]{43}": "High",  # SendGrid API Key
    "sk_live_[0-9a-zA-Z]{24}": "High",  # Stripe Live Secret Key
    "sk_test_[0-9a-zA-Z]{24}": "High",  # Stripe Test Secret Key
    "EAACEdEose0cBA[0-9A-Za-z]+": "High",  # Facebook Access Token
    "ya29\\.[0-9A-Za-z\\-_]+": "High",  # Google OAuth Access Token
    "AIza[0-9A-Za-z\\-_]{35}": "High",  # Google API Key
    "shppa_[0-9a-fA-F]{32}": "High",  # Shopify Private App Access Token
    "xoxb-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Bot Token
    "xoxp-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack User Token
    "xoxe-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Legacy Token
    "xoxs-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack App Token
    "ghp_[0-9a-zA-Z]{36}": "High",  # GitHub Personal Access Token
    "ghs_[0-9a-zA-Z]{36}": "High",  # GitHub Server-to-Server Token
    "glpat-[0-9a-zA-Z\\-_]{20}": "High",  # GitLab Personal Access Token
    "sq0atp-[0-9A-Za-z\\-_]{22}": "High",  # Square Access Token
    "sq0csp-[0-9A-Za-z\\-_]{43}": "High",  # Square OAuth Secret
    "dp\\.prod\\.[0-9a-zA-Z\\-_]{64}": "High",  # Datadog API Key
    "r1_[0-9a-zA-Z]{32}": "High",  # Rollbar Access Token
    "sentry_dsn=[0-9a-zA-Z]{32}": "High",  # Sentry DSN
    "oauth2-[0-9a-zA-Z]{32}": "High",  # OAuth 2.0 Token
    "slack_api_token=[0-9a-zA-Z]{24}": "High",  # Slack API Token
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_token=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Token
    "circleci_token=[0-9a-zA-Z]{40}": "High",  # CircleCI Token
    "github_token=[0-9a-zA-Z]{40}": "High",  # GitHub Token
    "bitbucket_token=[0-9a-zA-Z]{40}": "High",  # Bitbucket Token
    "digitalocean_token=[0-9a-zA-Z]{64}": "High",  # DigitalOcean Token
    "aws_secret_access_key=[0-9a-zA-Z/+=]{40}": "High",  # AWS Secret Access Key
    "gcp_service_account_key=[0-9a-zA-Z-_]{64}": "High",  # GCP Service Account Key
    "azure_storage_account_key=[0-9a-zA-Z+/=]{88}": "High",  # Azure Storage Account Key
    "twilio_auth_token=[0-9a-fA-F]{32}": "High",  # Twilio Auth Token
    "sendgrid_api_key=[0-9a-zA-Z]{69}": "High",  # SendGrid API Key
    "mailgun_api_key=[0-9a-zA-Z]{32}": "High",  # Mailgun API Key
    "stripe_api_key=[0-9a-zA-Z]{24}": "High",  # Stripe API Key
    "github_client_secret=[0-9a-zA-Z]{40}": "High",  # GitHub Client Secret
    "facebook_app_secret=[0-9a-zA-Z]{32}": "High",  # Facebook App Secret
    "twitter_api_secret=[0-9a-zA-Z]{40}": "High",  # Twitter API Secret
    "google_api_key=[0-9A-Za-z-_]{35}": "High",  # Google API Key
    "slack_signing_secret=[0-9a-zA-Z]{32}": "High",  # Slack Signing Secret
    "shopify_api_key=[0-9a-zA-Z]{32}": "High",  # Shopify API Key
    "paypal_client_secret=[0-9a-zA-Z]{64}": "High",  # PayPal Client Secret
    "dropbox_api_key=[0-9a-zA-Z]{15}": "High",  # Dropbox API Key
    "box_api_key=[0-9a-zA-Z]{32}": "High",  # Box API Key
    "asana_access_token=[0-9a-zA-Z]{32}": "High",  # Asana Access Token
    "trello_api_key=[0-9a-zA-Z]{32}": "High",  # Trello API Key
    "jira_api_token=[0-9a-zA-Z]{24}": "High",  # Jira API Token
    "datadog_api_key=[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    "newrelic_api_key=[0-9a-zA-Z]{40}": "High",  # New Relic API Key
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_api_key=[0-9a-zA-Z]{20}": "High",    # PagerDuty API Key
    # General Secrets
    "password=\"[^\"]+\"": "High",  # البحث عن password="أي قيمة"
    "token=\"[^\"]+\"": "High",     # البحث عن token="أي قيمة"
    "api_key=\"[^\"]+\"": "High",   # البحث عن api_key="أي قيمة"
    "secret=\"[^\"]+\"": "High",    # البحث عن secret="أي قيمة"
    "access_token=\"[^\"]+\"": "High",  # البحث عن access_token="أي قيمة"
    "client_id=\"[^\"]+\"": "High",  # البحث عن client_id="أي قيمة"
    "client_secret=\"[^\"]+\"": "High",  # البحث عن client_secret="أي قيمة"

    # JSON Format
    "\"password\":\"[^\"]+\"": "High",  # البحث عن "password":"أي قيمة"
    "\"token\":\"[^\"]+\"": "High",     # البحث عن "token":"أي قيمة"
    "\"api_key\":\"[^\"]+\"": "High",   # البحث عن "api_key":"أي قيمة"
    "\"secret\":\"[^\"]+\"": "High",    # البحث عن "secret":"أي قيمة"
    "\"access_token\":\"[^\"]+\"": "High",  # البحث عن "access_token":"أي قيمة"
    "\"client_id\":\"[^\"]+\"": "High",  # البحث عن "client_id":"أي قيمة"
    "\"client_secret\":\"[^\"]+\"": "High",  # البحث عن "client_secret":"أي قيمة"

    # باقي الكلمات المهمة
    "affirm_private": "High",
    "api_key": "High",
    "secret": "High",
    "private": "Medium",
    "token": "Medium",
    "sk_live": "High",  # Stripe Live Secret Key
    "pk_live": "Medium",  # Stripe Live Public Key
    "ghp": "High",  # GitHub Personal Access Token
    "xox": "High",  # Slack Token
    "AIza": "High",  # Google API Key
    "AC[a-zA-Z0-9]{32}": "High",  # Twilio Account SID
    "SG\\.[a-zA-Z0-9_]{22}\\.[a-zA-Z0-9_-]{43}": "High",  # SendGrid API Key
    "key-[0-9a-zA-Z]{32}": "High",  # Mailgun API Key
    "AKIA[0-9A-Z]{16}": "High",  # AWS Access Key ID
    "amzn\\.mws\\.[0-9a-zA-Z._%+-]{30,50}": "High",  # Amazon MWS Auth Token
    "EAACEdEose0cBA[0-9A-Za-z]+": "High",  # Facebook Access Token
    "ya29\\.[0-9A-Za-z\\-_]+": "High",  # Google OAuth Access Token
    "shppa_[0-9a-fA-F]{32}": "High",  # Shopify Private App Access Token
    "sq0atp-[0-9A-Za-z\\-_]{22}": "High",  # Square Access Token
    "sq0csp-[0-9A-Za-z\\-_]{43}": "High",  # Square OAuth Secret
    "dpk_live_[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    "sk_[live|test]_[0-9a-zA-Z]{24}": "High",  # Stripe API Key
    "r1_[0-9a-zA-Z]{32}": "High",  # Rollbar Access Token
    "sentry_dsn=[0-9a-zA-Z]{32}": "High",  # Sentry DSN
    "oauth2-[0-9a-zA-Z]{32}": "High",  # OAuth 2.0 Token
    "slack_api_token=[0-9a-zA-Z]{24}": "High",  # Slack API Token
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_token=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Token
    "circleci_token=[0-9a-zA-Z]{40}": "High",  # CircleCI Token
    "github_token=[0-9a-zA-Z]{40}": "High",  # GitHub Token
    "bitbucket_token=[0-9a-zA-Z]{40}": "High",  # Bitbucket Token
    "digitalocean_token=[0-9a-zA-Z]{64}": "High",  # DigitalOcean Token
    "aws_secret_access_key=[0-9a-zA-Z/+=]{40}": "High",  # AWS Secret Access Key
    "gcp_service_account_key=[0-9a-zA-Z-_]{64}": "High",  # GCP Service Account Key
    "azure_storage_account_key=[0-9a-zA-Z+/=]{88}": "High",  # Azure Storage Account Key
    "twilio_auth_token=[0-9a-fA-F]{32}": "High",  # Twilio Auth Token
    "sendgrid_api_key=[0-9a-zA-Z]{69}": "High",  # SendGrid API Key
    "mailgun_api_key=[0-9a-zA-Z]{32}": "High",  # Mailgun API Key
    "stripe_api_key=[0-9a-zA-Z]{24}": "High",  # Stripe API Key
    "github_client_secret=[0-9a-zA-Z]{40}": "High",  # GitHub Client Secret
    "facebook_app_secret=[0-9a-zA-Z]{32}": "High",  # Facebook App Secret
    "twitter_api_secret=[0-9a-zA-Z]{40}": "High",  # Twitter API Secret
    "google_api_key=[0-9A-Za-z-_]{35}": "High",  # Google API Key
    "slack_signing_secret=[0-9a-zA-Z]{32}": "High",  # Slack Signing Secret
    "shopify_api_key=[0-9a-zA-Z]{32}": "High",  # Shopify API Key
    "paypal_client_secret=[0-9a-zA-Z]{64}": "High",  # PayPal Client Secret
    "dropbox_api_key=[0-9a-zA-Z]{15}": "High",  # Dropbox API Key
    "box_api_key=[0-9a-zA-Z]{32}": "High",  # Box API Key
    "asana_access_token=[0-9a-zA-Z]{32}": "High",  # Asana Access Token
    "trello_api_key=[0-9a-zA-Z]{32}": "High",  # Trello API Key
    "jira_api_token=[0-9a-zA-Z]{24}": "High",  # Jira API Token
    "datadog_api_key=[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    "newrelic_api_key=[0-9a-zA-Z]{40}": "High",  # New Relic API Key
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_api_key=[0-9a-zA-Z]{20}": "High",  # PagerDuty API Key
     "ABTasty[_-]?API[_-]?Key": "High",
    # Algolia API key
    "Algolia[_-]?API[_-]?key": "High",

    # Amplitude API Keys
    "Amplitude[_-]?API[_-]?Keys": "High",

    # Asana Access token
    "Asana[_-]?Access[_-]?token": "High",

    # AWS Access Key ID and Secret
    "AWS[_-]?Access[_-]?Key[_-]?ID": "High",
    "AWS[_-]?Secret[_-]?Access[_-]?Key": "High",

    # Azure Application Insights APP ID and API Key
    "Azure[_-]?Application[_-]?Insights[_-]?APP[_-]?ID": "High",
    "Azure[_-]?Application[_-]?Insights[_-]?API[_-]?Key": "High",

    # Bazaarvoice Passkey
    "Bazaarvoice[_-]?Passkey": "High",

    # Bing Maps API Key
    "Bing[_-]?Maps[_-]?API[_-]?Key": "High",

    # Bit.ly Access token
    "Bit\\.ly[_-]?Access[_-]?token": "High",

    # Branch.io Key and Secret
    "Branch\\.io[_-]?Key": "High",
    "Branch\\.io[_-]?Secret": "High",

    # BrowserStack Access Key
    "BrowserStack[_-]?Access[_-]?Key": "High",

    # Buildkite Access token
    "Buildkite[_-]?Access[_-]?token": "High",

    # ButterCMS API Key
    "ButterCMS[_-]?API[_-]?Key": "High",

    # Calendly API Key
    "Calendly[_-]?API[_-]?Key": "High",

    # Contentful Access Token
    "Contentful[_-]?Access[_-]?Token": "High",

    # CircleCI Access Token
    "CircleCI[_-]?Access[_-]?Token": "High",

    # Cloudflare API key
    "Cloudflare[_-]?API[_-]?key": "High",

    # Cypress record key
    "Cypress[_-]?record[_-]?key": "High",

    # DataDog API key
    "DataDog[_-]?API[_-]?key": "High",

    # Delighted API key
    "Delighted[_-]?API[_-]?key": "High",

    # Deviant Art Access Token
    "Deviant[_-]?Art[_-]?Access[_-]?Token": "High",

    # Deviant Art Secret
    "Deviant[_-]?Art[_-]?Secret": "High",

    # Dropbox API
    "Dropbox[_-]?API": "High",

    # Facebook Access Token
    "Facebook[_-]?Access[_-]?Token": "High",

    # Facebook AppSecret
    "Facebook[_-]?AppSecret": "High",

    # Firebase
    "Firebase[_-]?API[_-]?Key": "High",

    # Firebase Cloud Messaging (FCM)
    "Firebase[_-]?Cloud[_-]?Messaging[_-]?\\(FCM\\)": "High",

    # FreshDesk API Key
    "FreshDesk[_-]?API[_-]?Key": "High",

    # Github client id and client secret
    "Github[_-]?client[_-]?id": "High",
    "Github[_-]?client[_-]?secret": "High",

    # GitHub private SSH key
    "GitHub[_-]?private[_-]?SSH[_-]?key": "High",

    # Github Token
    "Github[_-]?Token": "High",

    # Gitlab personal access token
    "Gitlab[_-]?personal[_-]?access[_-]?token": "High",

    # GitLab runner registration token
    "GitLab[_-]?runner[_-]?registration[_-]?token": "High",

    # Google Cloud Service Account credentials
    "Google[_-]?Cloud[_-]?Service[_-]?Account[_-]?credentials": "High",

    # Google Maps API key
    "Google[_-]?Maps[_-]?API[_-]?key": "High",

    # Google Recaptcha key
    "Google[_-]?Recaptcha[_-]?key": "High",

    # Grafana Access Token
    "Grafana[_-]?Access[_-]?Token": "High",

    # Help Scout OAUTH
    "Help[_-]?Scout[_-]?OAUTH": "High",

    # Heroku API key
    "Heroku[_-]?API[_-]?key": "High",

    # HubSpot API key
    "HubSpot[_-]?API[_-]?key": "High",

    # Infura API key
    "Infura[_-]?API[_-]?key": "High",

    # Instagram Access Token
    "Instagram[_-]?Access[_-]?Token": "High",

    # Instagram Basic Display API
    "Instagram[_-]?Basic[_-]?Display[_-]?API": "High",

    # Instagram Graph API
    "Instagram[_-]?Graph[_-]?API": "High",

    # Ipstack API Key
    "Ipstack[_-]?API[_-]?Key": "High",

    # Iterable API Key
    "Iterable[_-]?API[_-]?Key": "High",

    # JumpCloud API Key
    "JumpCloud[_-]?API[_-]?Key": "High",

    # Keen.io API Key
    "Keen\\.io[_-]?API[_-]?Key": "High",

    # LinkedIn OAUTH
    "LinkedIn[_-]?OAUTH": "High",

    # Lokalise API Key
    "Lokalise[_-]?API[_-]?Key": "High",

    # Loqate API Key
    "Loqate[_-]?API[_-]?Key": "High",

    # MailChimp API Key
    "MailChimp[_-]?API[_-]?Key": "High",

    # MailGun Private Key
    "MailGun[_-]?Private[_-]?Key": "High",

    # Mapbox API key
    "Mapbox[_-]?API[_-]?key": "High",

    # Microsoft Azure Tenant
    "Microsoft[_-]?Azure[_-]?Tenant": "High",

    # Microsoft Shared Access Signatures (SAS)
    "Microsoft[_-]?Shared[_-]?Access[_-]?Signatures[_-]?\\(SAS\\)": "High",

    # Microsoft Teams Webhook
    "Microsoft[_-]?Teams[_-]?Webhook": "High",

    # New Relic Personal API Key (NerdGraph)
    "New[_-]?Relic[_-]?Personal[_-]?API[_-]?Key[_-]?\\(NerdGraph\\)": "High",

    # New Relic REST API
    "New[_-]?Relic[_-]?REST[_-]?API": "High",

    # NPM token
    "NPM[_-]?token": "High",

    # OpsGenie API Key
    "OpsGenie[_-]?API[_-]?Key": "High",

    # Pagerduty API token
    "Pagerduty[_-]?API[_-]?token": "High",

    # Paypal client id and secret key
    "Paypal[_-]?client[_-]?id": "High",
    "Paypal[_-]?secret[_-]?key": "High",

    # Pendo Integration Key
    "Pendo[_-]?Integration[_-]?Key": "High",

    # PivotalTracker API Token
    "PivotalTracker[_-]?API[_-]?Token": "High",

    # Razorpay API key and secret key
    "Razorpay[_-]?API[_-]?key": "High",
    "Razorpay[_-]?secret[_-]?key": "High",

    # Salesforce API key
    "Salesforce[_-]?API[_-]?key": "High",

    # SauceLabs Username and access Key
    "SauceLabs[_-]?Username": "High",
    "SauceLabs[_-]?access[_-]?Key": "High",

    # SendGrid API Token
    "SendGrid[_-]?API[_-]?Token": "High",

    # Shodan.io
    "Shodan\\.io[_-]?API[_-]?Key": "High",

    # Slack API token
    "Slack[_-]?API[_-]?token": "High",

    # Slack Webhook
    "Slack[_-]?Webhook": "High",

    # Sonarcloud
    "Sonarcloud[_-]?API[_-]?Key": "High",

    # Spotify Access Token
    "Spotify[_-]?Access[_-]?Token": "High",

    # Square
    "Square[_-]?API[_-]?Key": "High",

    # Stripe Live Token
    "Stripe[_-]?Live[_-]?Token": "High",

    # Telegram Bot API Token
    "Telegram[_-]?Bot[_-]?API[_-]?Token": "High",

    # Travis CI API token
    "Travis[_-]?CI[_-]?API[_-]?token": "High",

    # Twilio Account_sid and Auth token
    "Twilio[_-]?Account_sid": "High",
    "Twilio[_-]?Auth[_-]?token": "High",

    # Twitter API Secret
    "Twitter[_-]?API[_-]?Secret": "High",

    # Twitter Bearer token
    "Twitter[_-]?Bearer[_-]?token": "High",

    # Visual Studio App Center API Token
    "Visual[_-]?Studio[_-]?App[_-]?Center[_-]?API[_-]?Token": "High",

    # WakaTime API Key
    "WakaTime[_-]?API[_-]?Key": "High",

    # WeGlot Api Key
    "WeGlot[_-]?Api[_-]?Key": "High",

    # WPEngine API Key
    "WPEngine[_-]?API[_-]?Key": "High",

    # YouTube API Key
    "YouTube[_-]?API[_-]?Key": "High",

    # Zapier Webhook Token
    "Zapier[_-]?Webhook[_-]?Token": "High",

    # Zendesk Access token
    "Zendesk[_-]?Access[_-]?token": "High",

    # Zendesk API key
    "Zendesk[_-]?API[_-]?key": "High",# General Secrets
    "api_key": "High",
    "api_secret": "High",
    "access_token": "High",
    "refresh_token": "High",
    "oauth_token": "High",
    "bearer_token": "High",
    "client_id": "High",
    "client_secret": "High",
    "session_token": "High",
    "jwt_token": "High",
    "encryption_key": "High",
    "private_key": "High",
    "public_key": "High",
    "ssh_key": "High",
    "pgp_key": "High",
    "rsa_key": "High",
    "ssl_certificate": "High",
    "jwt_secret": "High",
    "session_secret": "High",

    # Cloud Provider Secrets
    "aws_access_key_id": "High",
    "aws_secret_access_key": "High",
    "aws_session_token": "High",
    "gcp_service_account_key": "High",
    "azure_storage_account_key": "High",
    "digitalocean_token": "High",
    "heroku_api_key": "High",
    "ibm_cloud_api_key": "High",
    "oracle_cloud_api_key": "High",
    "alibaba_cloud_access_key": "High",

    # Database Credentials
    "db_password": "High",
    "database_url": "High",
    "mongodb_uri": "High",
    "postgresql_url": "High",
    "mysql_password": "High",
    "redis_password": "High",
    "cassandra_password": "High",
    "elasticsearch_password": "High",

    # Payment Gateway Keys
    "stripe_api_key": "High",
    "paypal_client_secret": "High",
    "square_access_token": "High",
    "braintree_private_key": "High",
    "adyen_api_key": "High",
    "authorize_net_api_key": "High",
    "worldpay_api_key": "High",

    # Social Media Tokens
    "facebook_access_token": "High",
    "twitter_api_key": "High",
    "instagram_access_token": "High",
    "linkedin_api_key": "High",
    "pinterest_access_token": "High",
    "tiktok_access_token": "High",
    "snapchat_access_token": "High",

    # Version Control Tokens
    "github_token": "High",
    "gitlab_token": "High",
    "bitbucket_token": "High",
    "svn_password": "High",
    "mercurial_token": "High",

    # CI/CD Secrets
    "circleci_token": "High",
    "travisci_token": "High",
    "jenkins_token": "High",
    "gitlab_ci_token": "High",
    "azure_devops_token": "High",
    "bamboo_token": "High",

    # Messaging Services
    "slack_api_token": "High",
    "slack_webhook_url": "High",
    "twilio_auth_token": "High",
    "sendgrid_api_key": "High",
    "mailgun_api_key": "High",
    "amazon_ses_key": "High",
    "nexmo_api_key": "High",
    "messagebird_api_key": "High",

    # Monitoring and Logging
    "datadog_api_key": "High",
    "newrelic_api_key": "High",
    "splunk_token": "High",
    "loggly_token": "High",
    "papertrail_token": "High",
    "grafana_api_key": "High",

    # Infrastructure as Code
    "terraform_api_key": "High",
    "pulumi_api_key": "High",
    "ansible_vault_password": "High",
    "chef_server_key": "High",
    "puppet_master_key": "High",

    # Container Orchestration
    "kubernetes_secret": "High",
    "docker_registry_password": "High",
    "helm_repository_password": "High",
    "rancher_api_key": "High",

    # Security Tools
    "vault_token": "High",
    "hashicorp_vault_key": "High",
    "sonarqube_token": "High",
    "snyk_api_key": "High",
    "nessus_api_key": "High",

    # Other Common Secrets
    "affirm_private": "High",
    "affirm_public": "High",
    "internal_api_key": "High",
    "production_db_password": "High",
    "staging_api_key": "High",
    "development_secret": "High",
    "test_token": "High",

    # Regex Patterns for Common Secrets
    "AKIA[0-9A-Z]{16}": "High",  # AWS Access Key ID
    "SG\\.[a-zA-Z0-9_]{22}\\.[a-zA-Z0-9_-]{43}": "High",  # SendGrid API Key
    "sk_live_[0-9a-zA-Z]{24}": "High",  # Stripe Live Secret Key
    "sk_test_[0-9a-zA-Z]{24}": "High",  # Stripe Test Secret Key
    "EAACEdEose0cBA[0-9A-Za-z]+": "High",  # Facebook Access Token
    "ya29\\.[0-9A-Za-z\\-_]+": "High",  # Google OAuth Access Token
    "AIza[0-9A-Za-z\\-_]{35}": "High",  # Google API Key
    "shppa_[0-9a-fA-F]{32}": "High",  # Shopify Private App Access Token
    "xoxb-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Bot Token
    "xoxp-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack User Token
    "xoxe-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack Legacy Token
    "xoxs-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{24}": "High",  # Slack App Token
    "ghp_[0-9a-zA-Z]{36}": "High",  # GitHub Personal Access Token
    "ghs_[0-9a-zA-Z]{36}": "High",  # GitHub Server-to-Server Token
    "glpat-[0-9a-zA-Z\\-_]{20}": "High",  # GitLab Personal Access Token
    "sq0atp-[0-9A-Za-z\\-_]{22}": "High",  # Square Access Token
    "sq0csp-[0-9A-Za-z\\-_]{43}": "High",  # Square OAuth Secret
    "dp\\.prod\\.[0-9a-zA-Z\\-_]{64}": "High",  # Datadog API Key
    "r1_[0-9a-zA-Z]{32}": "High",  # Rollbar Access Token
    "github_client_secret=[0-9a-zA-Z]{40}": "High",  # GitHub Client Secret
    "facebook_app_secret=[0-9a-zA-Z]{32}": "High",  # Facebook App Secret
    "twitter_api_secret=[0-9a-zA-Z]{40}": "High",  # Twitter API Secret
    "google_api_key=[0-9A-Za-z-_]{35}": "High",  # Google API Key
    "slack_signing_secret=[0-9a-zA-Z]{32}": "High",  # Slack Signing Secret
    "shopify_api_key=[0-9a-zA-Z]{32}": "High",  # Shopify API Key
    "paypal_client_secret=[0-9a-zA-Z]{64}": "High",  # PayPal Client Secret
    "dropbox_api_key=[0-9a-zA-Z]{15}": "High",  # Dropbox API Key
    "box_api_key=[0-9a-zA-Z]{32}": "High",  # Box API Key
    "asana_access_token=[0-9a-zA-Z]{32}": "High",  # Asana Access Token
    "trello_api_key=[0-9a-zA-Z]{32}": "High",  # Trello API Key
    "jira_api_token=[0-9a-zA-Z]{24}": "High",  # Jira API Token
    "datadog_api_key=[0-9a-zA-Z]{32}": "High",  # Datadog API Key
    "newrelic_api_key=[0-9a-zA-Z]{40}": "High",  # New Relic API Key
    "heroku_api_key=[0-9a-zA-Z]{32}": "High",  # Heroku API Key
    "pagerduty_api_key=[0-9a-zA-Z]{20}": "High"  # PagerDuty API Key
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
