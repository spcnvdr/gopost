curl -X POST https://IP:PORT/upload -F 'files=@./myfile.txt' -F 'files=@./myfile.pdf' --insecure

curl -X POST http://IP:PORT/upload -F 'files=@./myfile.txt' -F 'files=@./myfile.pdf'
