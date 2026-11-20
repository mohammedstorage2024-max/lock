const serverless = require('serverless-http');
const { connectLambda } = require('@netlify/blobs');
const { app } = require('../../server');

const expressHandler = serverless(app);

exports.handler = (event, context) => {
  // Lambda-compatible Netlify functions need this to initialize Blobs access.
  connectLambda(event);
  return expressHandler(event, context);
};
