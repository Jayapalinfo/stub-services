# Router stub

Use this project as a guideline / fork for your Employee-Edge-Router stub.  
The stub is based on WireMock so can easily be extended with custom testdata.

## Why are you providing a stub?
For the Router we provide a stub because we can imagine the signing of the header is not so straightforward.  
With this project we hope to give you a better starting point in stubbing the Router.

## Usage
### Adding routes
Add your testdata to the mappings directory: 
>Router-stub/src/main/resources/testdata/mappings

There is an [example](src/main/resources/testdata/mappings/getbookingrequest.json) that you can use to write your own proxy rules.

## Call the stub
You can call the stub with curl for example like:
```bash
curl --cookie "x-employee=application%3Bfunction-a%3Aapplication%3Bfunction-b%3Aapplication%3Bfunction-c" http://localhost:8091/the/external/path/you/configured/with/wiremock/proxy
```
