import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
import logging
from config import UPLOAD_WINDOW_START_DAY, UPLOAD_WINDOW_END_DAY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define IST timezone
IST = timezone(timedelta(hours=5, minutes=30))

class EmailService:
    def __init__(self):
        # Try to import from email_config.py first, fallback to environment variables
        try:
            from email_config import SMTP_CONFIG
            self.smtp_host = SMTP_CONFIG.get('SMTP_HOST', '')
            self.smtp_port = int(SMTP_CONFIG.get('SMTP_PORT', 587))
            self.smtp_username = SMTP_CONFIG.get('SMTP_USERNAME', '')
            self.smtp_password = SMTP_CONFIG.get('SMTP_PASSWORD', '')
            self.from_email = SMTP_CONFIG.get('SMTP_FROM_EMAIL', self.smtp_username)
            self.from_name = SMTP_CONFIG.get('SMTP_FROM_NAME', 'MIS System')
            logger.info("Email configuration loaded from email_config.py")
        except (ImportError, Exception) as e:
            # Fallback to environment variables if email_config.py doesn't exist or has errors
            logger.warning(f"Could not load email_config.py ({str(e)}), using environment variables")
            self.smtp_host = os.environ.get('SMTP_HOST', '')
            self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
            self.smtp_username = os.environ.get('SMTP_USERNAME', '')
            self.smtp_password = os.environ.get('SMTP_PASSWORD', '')
            self.from_email = os.environ.get('SMTP_FROM_EMAIL', self.smtp_username)
            self.from_name = os.environ.get('SMTP_FROM_NAME', 'MIS System')

    def is_configured(self):
        """Check if email service is properly configured"""
        return all([
            self.smtp_host,
            self.smtp_port,
            self.smtp_username,
            self.smtp_password,
            self.from_email
        ])

    def send_email(self, to_email, subject, html_content, text_content=None):
        """
        Send an email via SMTP

        Args:
            to_email: Recipient email address or list of addresses
            subject: Email subject
            html_content: HTML version of the email body
            text_content: Plain text version (optional, falls back to HTML)

        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.is_configured():
            logger.warning("Email service not configured. Skipping email send.")
            return False, "Email service not configured. Please set SMTP environment variables."

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"

            # Handle multiple recipients
            if isinstance(to_email, list):
                msg['To'] = ', '.join(to_email)
                recipients = to_email
            else:
                msg['To'] = to_email
                recipients = [to_email]

            # Add text and HTML parts
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                msg.attach(text_part)

            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

            logger.info(f"Email sent successfully to {recipients}")
            return True, f"Email sent successfully to {len(recipients)} recipient(s)"

        except smtplib.SMTPAuthenticationError:
            error_msg = "SMTP Authentication failed. Please check your username and password."
            logger.error(error_msg)
            return False, error_msg
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error occurred: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Failed to send email: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def send_upload_window_notification(self, hod_users, app_url=None):
        """
        Send MIS upload window notification to all HOD users

        Args:
            hod_users: List of User objects with HOD role
            app_url: Application URL for links in email (optional)

        Returns:
            tuple: (success_count: int, total_count: int, messages: list)
        """
        if not self.is_configured():
            return 0, 0, ["Email service not configured"]

        success_count = 0
        messages = []

        if not app_url:
            app_url = "your MIS system"

        current_month = datetime.now().strftime('%B %Y')

        subject = f"MIS Upload Window Now Open - {current_month}"

        for user in hod_users:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background-color: #4F46E5; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
                    .content {{ background-color: #f9fafb; padding: 30px; border: 1px solid #e5e7eb; }}
                    .alert-box {{ background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }}
                    .footer {{ background-color: #f3f4f6; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; font-size: 12px; color: #6b7280; }}
                    .button {{ display: inline-block; background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
                    ul {{ padding-left: 20px; }}
                    li {{ margin: 8px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2 style="margin: 0;">MIS Upload Window Notification</h2>
                    </div>
                    <div class="content">
                        <p>Dear {user.Username},</p>

                        <div class="alert-box">
                            <strong>⏰ Important Reminder:</strong> The MIS upload window for <strong>{current_month}</strong> is now open!
                        </div>

                        <p>You can now upload your department's MIS reports for the current month.</p>

                        <h3>Upload Window Details:</h3>
                        <ul>
                            <li><strong>Opens:</strong> {UPLOAD_WINDOW_START_DAY}st of each month</li>
                            <li><strong>Closes:</strong> {UPLOAD_WINDOW_END_DAY}th of each month</li>
                            <li><strong>Your Department:</strong> {user.department.DeptName}</li>
                        </ul>

                        <h3>Important Notes:</h3>
                        <ul>
                            <li>Ensure all data is accurate and complete before uploading</li>
                            <li>Use the correct template for your department</li>
                            <li>Uploads will be validated automatically upon submission</li>
                            <li>Late submissions after the {UPLOAD_WINDOW_END_DAY}th will not be accepted</li>
                        </ul>

                        <li><strong>Sent to:</strong> {user.Email}</li>
                        <li><strong>Timestamp:</strong> {datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S IST')}</li>

                        <p>If you have any questions or need assistance, please contact the system administrator.</p>

                        <p>Best regards,<br>
                        <strong>MIS System Team</strong></p>
                    </div>
                    <div class="footer">
                        This is an automated notification from the MIS Upload System.<br>
                        Please do not reply to this email.
                    </div>
                </div>
            </body>
            </html>
            """

            text_content = f"""
MIS Upload Window Now Open - {current_month}

Dear {user.Username},

⏰ IMPORTANT REMINDER: The MIS upload window for {current_month} is now open!

You can now upload your department's MIS reports for the current month.

Upload Window Details:
- Opens: {UPLOAD_WINDOW_START_DAY}st of each month
- Closes: {UPLOAD_WINDOW_END_DAY}th of each month
- Your Department: {user.department.DeptName}

Important Notes:
- Ensure all data is accurate and complete before uploading
- Use the correct template for your department
- Uploads will be validated automatically upon submission
- Late submissions after the {UPLOAD_WINDOW_END_DAY}th will not be accepted

- Sent to: {user.Email}
- Timestamp: {datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S IST')}

If you have any questions or need assistance, please contact the system administrator.


Best regards,
MIS System Team

---
This is an automated notification from the MIS Upload System.
Please do not reply to this email.
            """

            success, message = self.send_email(user.Email, subject, html_content, text_content)
            messages.append(f"{user.Username} ({user.Email}): {message}")

            if success:
                success_count += 1

        return success_count, len(hod_users), messages


# Global email service instance
email_service = EmailService()