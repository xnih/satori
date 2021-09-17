I have an hourly cronjob that calls satori-em2.sh and satori-em4.sh.  It kills the job every hour and starts it back up.  

When it runs at midnight it then rotates the logfile to the next day as well.

By no means perfect, but works well enough for what I need.  I also setup the email notification for when the server bounces for patches, or if it happens to crash out
