import hashlib
import hmac
import os

import six
from dotmap import DotMap
from errbot import BotPlugin, webhook
from github2gitlab.main import GitHub2GitLab


class Hub2Lab(BotPlugin):
    """
    hub2lab
    """

    def activate(self):
        """
        Triggers on plugin activation

        You should delete it if you're not using it to override any default behaviour
        """
        super(Hub2Lab, self).activate()

    def deactivate(self):
        """
        Triggers on plugin deactivation

        You should delete it if you're not using it to override any default behaviour
        """
        super(Hub2Lab, self).deactivate()

    def get_configuration_template(self):
        """
        Defines the configuration structure this plugin supports

        You should delete it if your plugin doesn't use any configuration like this
        """
        return {'mapping': {
            'github/repo': {
                'gitlab_url': 'https://example.gitlab.com',
                'gitlab_token': 'GITLAB_TOKEN',
                'gitlab_repo': 'namespace/repo',
                'github_token': 'GITHUB_TOKEN',
                'secret': 'GITHUB_WEBHOOK_SECRET'
            }
        }}

    def check_configuration(self, configuration):
        """
        Triggers when the configuration is checked, shortly before activation

        Raise a errbot.utils.ValidationException in case of an error

        You should delete it if you're not using it to override any default behaviour
        """
        # super(Hub2Lab, self).check_configuration(configuration)
        pass

    def callback_connect(self):
        """
        Triggers when bot is connected

        You should delete it if you're not using it to override any default behaviour
        """
        pass

    def callback_message(self, message):
        """
        Triggered for every received message that isn't coming from the bot itself

        You should delete it if you're not using it to override any default behaviour
        """
        pass

    def callback_botmessage(self, message):
        """
        Triggered for every message that comes from the bot itself

        You should delete it if you're not using it to override any default behaviour
        """
        pass

    def callback_presence(self, presence):
        if hasattr(presence, 'get_message') and presence.get_message() is not None:
            self.log.info(presence)

    @webhook('/hub2lab/webhook', raw=True)
    def github_webhook(self, incoming_request):
        """A webhook which simply returns 'Example'"""
        self.log.debug(incoming_request.json)

        # check if json payload is valid
        if not incoming_request.json:
            self.log.warn('Invalid JSON payload from github event')

        github_repo = incoming_request.json['repository']['full_name']
        if github_repo not in self.config['mapping']:
            self.log.warn('No configuration for github repo {}. Ignoring github event.'.format(github_repo))
            return

        # valid github signature
        if not self.verify_github_digest(
                incoming_request.data,
                self.config['mapping'][github_repo]['secret'],
                incoming_request.headers.get('X-Hub-Signature')):
            return "Invalid signature"

        return self.handle_github_event(incoming_request)

    def verify_github_digest(self, data, secret, signature):
        digest = hmac.new(secret.encode(), data, hashlib.sha1).hexdigest() if secret else None

        if digest is not None:
            sig_parts = signature.split('=', 1)
            if not isinstance(digest, six.text_type):
                digest = six.text_type(digest)

            if (len(sig_parts) < 2 or sig_parts[0] != 'sha1'
                    or not hmac.compare_digest(sig_parts[1], digest)):
                self.log.warn('Invalid signature')
                return False

        return True

    def handle_github_event(self, request):
        self.log.info('Got GitHub {} request.'.format(request.headers.get('X-GitHub-Event')))

        if 'zen' in request.json:
            return "Success"

        if 'pull_request' == request.headers.get('X-GitHub-Event') or 'push' == request.headers.get('X-GitHub-Event'):
            return self.sync_repos(request.json['repository']['full_name'])

    def sync_repos(self, github_repo):
        if github_repo not in self.config['mapping']:
            self.log.warn('No configuration for github repo {}. Ignoring github event.'.format(github_repo))
            return

        # GitHub2GitLab may change the current directory and when the command fails,
        # the current directory is not reverted back causing issues to the following
        # commands. So we need to set it to original one after exception
        cwd = os.getcwd()
        ret = None

        try:
            ret = GitHub2GitLab(DotMap({
                "gitlab_url": self.config['mapping'][github_repo]['gitlab_url'],
                "gitlab_token": self.config['mapping'][github_repo]['gitlab_token'],
                "gitlab_repo": self.config['mapping'][github_repo]['gitlab_repo'],
                "github_token": self.config['mapping'][github_repo]['github_token'],
                "github_repo": github_repo,
                "ssh_public_key": "",
            })).run()
        finally:
            os.chdir(cwd)

        return ret
