rm -rf /home/appuser/health/*
echo "X" > /home/appuser/health/ping
sleep 5
cat /home/appuser/health/pong