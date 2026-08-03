# 100101 - 404 burst
for i in {1..20}; do curl -s http://ubuntu-zrahman/admin$i > /dev/null; done

# 100103 - scanner user-agent
curl -s -A "sqlmap/1.0" http://ubuntu-zrahman/ > /dev/null

# 100100 - SSH brute force
for i in {1..8}; do ssh -o StrictHostKeyChecking=no baduser@ubuntu-zrahman; done