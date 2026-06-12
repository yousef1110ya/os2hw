# OS2 Project 

to run this project , we only need to run the docker-compose file and nothing more . 

>**NOTES**: 
- the server name is os2.com and it's connected to local host so both os2.com and localhost will work just fine 
- it only serves on https on port 443 so no need to add port 8080 or stuff like that for the system . 
- the containers are connected to each others , so they will not work until the other one is working making the wake up time harder 
- for the webapp to fully work , add the os2.com to hosts and bind it to 127.0.0.1 
