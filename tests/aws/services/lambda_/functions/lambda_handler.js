exports.handler = async (event) => {
   console.log(JSON.stringify(event))
   return {
     statusCode: 200,
     body: JSON.stringify(`response from localemu lambda: ${JSON.stringify(event)}`),
     isBase64Encoded: false,
     headers: {}
   }
}
