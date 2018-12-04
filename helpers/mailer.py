'''
Sends emails.
'''
import datetime
from string import Template
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import config

class Mailer():
    email_template_html = None
    email_template_plain = None

    def __init__(self):
        self.config = config['email']

    def send(self, content_key, to_email, **parameters):
        # Get template
        if self.email_template_html is None or self.email_template_plain is None:
            self.email_template_html, self.email_template_plain = self.get_template()

        # Set up the SMTP server
        s = smtplib.SMTP(host=self.config['account']['host'], port=self.config['account']['port'])
        s.starttls()
        s.login(self.config['account']['username'], self.config['account']['password'])

        # Build email
        email = MIMEMultipart()
        title = Template(self.config['contents'][content_key]['EMAIL_TITLE'])
        content_html = Template(self.config['contents'][content_key]['EMAIL_CONTENT_HTML'])
        content_plain = Template(self.config['contents'][content_key]['EMAIL_CONTENT_PLAIN'])

        # Replace parameters in content
        title = title.substitute(parameters)
        content_html = content_html.substitute(parameters)
        content_plain = content_plain.substitute(parameters)

        # Replace parameters in email
        now = datetime.datetime.now()
        message_html = self.email_template_html.substitute(EMAIL_TITLE=title, EMAIL_CONTENT=content_html, CURRENT_YEAR=now.year)
        message_plain = self.email_template_plain.substitute(EMAIL_TITLE=title, EMAIL_CONTENT=content_plain, CURRENT_YEAR=now.year)

        # Set up the parameters of the email
        email['From']=self.config['account']['username']
        email['To']=to_email
        email['Subject']=title
        email.attach(MIMEText(message_html, 'html'))
        email.attach(MIMEText(message_plain, 'plain'))

        # send the message via the server set up earlier.
        s.send_message(email)

        del email

        # Terminate the SMTP session and close the connection
        s.quit()

    def get_template(self):
        with open(self.config['template']['html'], 'r', encoding='utf-8') as email_template_file:
            email_template_html = email_template_file.read()

        with open(self.config['template']['plain'], 'r', encoding='utf-8') as email_template_file:
            email_template_plain = email_template_file.read()

        return Template(email_template_html), Template(email_template_plain)
