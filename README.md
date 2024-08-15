Open dist folder in cmd
First run httpfs using: python httpfs.py [-d directory]

Second: Install go and then run 'go build router.go'
## GET Testing
Run using python httpc.py

#### 1. GET with query parameters

get "http://localhost:8080/"

get -v "http://localhost:8080/"

get -v "http://localhost:8080/test.txt"

#### 2. GET with headers

get -h Content-Type:application/json "http://localhost:8007/test.txt"

get -v -h Content-Type:application/json "http://localhost:8007/test.txt"

#### 3. Multiple Header Support [-h]*

get -v -h Content-Type:application/json -h Name:Isaac "http://localhost:8007/test.txt"

## POST Testing

#### 1. POST with inline data [-d]

post -h Content-Type:application/json -d "{\"Assignment\": 1}" "http://localhost:8007/test.txt"

post -v -h Content-Type:application/json -d "{\"Assignment\": 1}" "http://localhost:8007/test.txt"

post -h overwrite:True -d "{\"Assignment\": 1}" "http://localhost:8007/test.txt"

post -h overwrite:False -d "{\"Assignment\": 1}" "http://localhost:8007/test.txt"

## GET Testing with changing directory

get "http://localhost:8007/../"
