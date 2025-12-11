"""
Optional: Automated Monthly Email Notification Scheduler

This file shows how to set up automated monthly notifications.
To use this, you need to install APScheduler:
    uv add apscheduler

Then modify app.py to import and start this scheduler.
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import logging

logger = logging.getLogger(__name__)

def setup_scheduler(app, db):
    """
    Set up automated scheduler for monthly notifications
    
    Args:
        app: Flask application instance
        db: SQLAlchemy database instance
    
    Returns:
        scheduler: BackgroundScheduler instance
    """
    from app import User, Role
    from email_service import email_service
    
    def send_monthly_notifications():
        """Send MIS upload window notifications on the 1st of each month"""
        try:
            with app.app_context():
                hod_role = Role.query.filter_by(RoleName='HOD').first()
                
                if not hod_role:
                    logger.error("HOD role not found in database")
                    return
                
                hod_users = User.query.filter_by(RoleID=hod_role.RoleID, IsActive=True).all()
                
                if not hod_users:
                    logger.warning("No active HOD users found to notify")
                    return
                
                if not email_service.is_configured():
                    logger.error("Email service not configured. Cannot send notifications.")
                    return
                
                success_count, total_count, messages = email_service.send_upload_window_notification(hod_users)
                
                logger.info(f"Monthly notification sent: {success_count}/{total_count} successful")
                
                for msg in messages:
                    if 'error' in msg.lower() or 'failed' in msg.lower():
                        logger.error(f"Notification error: {msg}")
                    else:
                        logger.info(f"Notification: {msg}")
        
        except Exception as e:
            logger.error(f"Error in monthly notification job: {str(e)}")
    
    scheduler = BackgroundScheduler()
    
    # Schedule to run at 8:00 AM on the 1st of every month
    scheduler.add_job(
        send_monthly_notifications,
        trigger=CronTrigger(day=1, hour=8, minute=0),
        id='monthly_mis_notification',
        name='Send monthly MIS upload window notifications',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started successfully. Monthly notifications will be sent on the 1st of each month at 8:00 AM.")
    
    return scheduler


# Alternative: Manual testing function
def test_notification_manually(app):
    """
    Test the notification system manually
    Usage: python -c "from scheduler_setup import test_notification_manually; from app import app; test_notification_manually(app)"
    """
    from app import User, Role
    from email_service import email_service
    
    with app.app_context():
        hod_role = Role.query.filter_by(RoleName='HOD').first()
        if hod_role:
            hod_users = User.query.filter_by(RoleID=hod_role.RoleID, IsActive=True).all()
            success_count, total_count, messages = email_service.send_upload_window_notification(hod_users)
            print(f"\nNotification Test Results:")
            print(f"Sent to {success_count} out of {total_count} HOD users\n")
            for msg in messages:
                print(f"  - {msg}")


"""
INTEGRATION INSTRUCTIONS:

1. Install APScheduler:
   uv add apscheduler

2. Update app.py to include the scheduler:
   
   # At the top of app.py, after other imports:
   from scheduler_setup import setup_scheduler
   
   # At the bottom of app.py, before if __name__ == '__main__':
   scheduler = None
   
   # Inside if __name__ == '__main__':
   if __name__ == '__main__':
       init_db()
       scheduler = setup_scheduler(app, db)
       try:
           app.run(host='0.0.0.0', port=5000, debug=True)
       finally:
           if scheduler:
               scheduler.shutdown()

3. Ensure SMTP credentials are set in environment variables:
   - SMTP_HOST
   - SMTP_PORT
   - SMTP_USERNAME
   - SMTP_PASSWORD
   - SMTP_FROM_EMAIL
   - SMTP_FROM_NAME (optional)

4. Test manually:
   python -c "from scheduler_setup import test_notification_manually; from app import app; test_notification_manually(app)"

ALTERNATIVE: Use external cron services
If you prefer not to use in-app scheduling, you can use external services:
- cron-job.org: Set up a POST request to /send-upload-notifications
- GitHub Actions: Create a scheduled workflow
- Your server's crontab: 0 8 1 * * curl -X POST https://your-app/send-upload-notifications
"""
