# tapzzi-api

## Steps to run the project locally
Step 1: Install virtual environment by running following commands in the terminal 

`1.` ``` python3.9 -m venv --without-pip virtual ```
`2.` ``` source virtual/bin/activate ```

Step 2:
``` python main.py ```

## Steps to run the project through docker

Step 1: 
``` docker build -t tapzzi-backend . ```

Step 2: 
``` docker run -p 5000:5000 tapzzi-backend ```

If it does not run through this command, go to docker dektop and run your image at new port 5002
