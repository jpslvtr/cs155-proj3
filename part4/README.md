# Banking Monster-in-the-Middle

## How to run:
* You should have Docker installed from Project 2. If not, take a look at the Project 2 handout for instructions on how to install.
* To build the images that will be running the backend http and dns servers, run `bash start_images.sh` in this directory. If you modify any of the files in the network/ directory, you'll need to re-run this command; otherwise, you should only need to run this once.
* To test your `mitm.go` implementation, run `bash run_client.sh`. You'll need to re-run this command anytime you make changes to the `mitm.go` file and want to see the updated output.
* To stop your images once you're done with the project, run `bash stop_images.sh`. If you'd like to completely remove the unused images and containers from your machine (e.g. when you're done with the assignment and want to save space), do `docker system prune -a`.
* If any of the above commands gives you trouble, try running `docker system prune -a`. This will clean up files related to previous instances, in case they are causing issues with the build process.

Note: If you are on Linux, you will have to run the above commands with `sudo` privileges. 

## How to check:
`correct_mitm_output.txt` is what you should see after implementing the MITM completely (with the last line in network/dns/dns-server.go commented out - see note below). In other words, your output when running `bash run_client.sh` should match the contents of the `correct_mitm_output.txt` file, with the exception that the lines beginning with `tcpdump` or referencing packets captured/received/dropped don't need to exactly match.

## Other notes about the file structure:
* The only file you will need to edit is `mitm.go`. If you'd like you can uncomment the last line in network/dns/dns-server.go to see what responses the DNS server will ordinarily give, but **remember to comment it out again** when you write your own code, because it will mess up your output otherwise.
