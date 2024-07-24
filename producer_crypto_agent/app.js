const AWS = require('aws-sdk');
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

// Load configuration
const configPath = path.join(__dirname, 'config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

// Configure AWS SDK
AWS.config.update({ region: config.awsRegion || 'us-west-2' });
const s3 = new AWS.S3({ apiVersion: '2006-03-01' });
const sqs = new AWS.SQS({ apiVersion: '2012-11-05' });
const kms = new AWS.KMS({ apiVersion: '2014-11-01' });

// Initialize Express app
const app = express();
app.use(bodyParser.json());

// Endpoint to receive data and start the encryption and job process
app.post('/encrypt', async (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).send('Data is required');
  }

  try {
    // Encrypt the data
    const encryptedData = await encryptData(data);

    // Store encrypted data in S3
    const s3Key = await storeInS3(encryptedData);

    // Send job message to SQS
    await sendJobToSQS(s3Key);

    res.status(200).send('Data encrypted and job sent to SQS');
  } catch (err) {
    console.error('Error processing request:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Function to encrypt data using AWS KMS
async function encryptData(data) {
  const params = {
    KeyId: config.kmsKeyId,
    Plaintext: data
  };

  try {
    const result = await kms.encrypt(params).promise();
    return result.CiphertextBlob.toString('base64');
  } catch (err) {
    console.error('Error encrypting data:', err);
    throw err;
  }
}

// Function to store encrypted data in S3
async function storeInS3(encryptedData) {
  const s3Key = `encrypted-data-${Date.now()}.txt`;
  const params = {
    Bucket: config.s3Bucket,
    Key: s3Key,
    Body: encryptedData
  };

  try {
    await s3.putObject(params).promise();
    console.log(`Encrypted data stored in S3 with key: ${s3Key}`);
    return s3Key;
  } catch (err) {
    console.error('Error storing data in S3:', err);
    throw err;
  }
}

// Function to send a job message to SQS
async function sendJobToSQS(s3Key) {
  const params = {
    QueueUrl: config.sqsQueueUrl,
    MessageBody: JSON.stringify({ s3Key })
  };

  try {
    await sqs.sendMessage(params).promise();
    console.log(`Job message sent to SQS with S3 key: ${s3Key}`);
  } catch (err) {
    console.error('Error sending message to SQS:', err);
    throw err;
  }
}

// Start the server
const port = config.port || 3000;
app.listen(port, () => {
  console.log(`Producer crypto agent running on port ${port}`);
});
