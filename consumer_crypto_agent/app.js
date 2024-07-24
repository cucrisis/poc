const AWS = require('aws-sdk');
const axios = require('axios');

// Configure AWS SDK
AWS.config.update({ region: process.env.AWS_REGION || 'us-west-2' });
const sqs = new AWS.SQS({ apiVersion: '2012-11-05' });
const kms = new AWS.KMS({ apiVersion: '2014-11-01' });

// Your SQS queue URL and KMS key ID from environment variables
const queueUrl = process.env.SQS_QUEUE_URL;
const kmsKeyId = process.env.KMS_KEY_ID;

// Function to poll SQS for messages
async function pollQueue() {
  const params = {
    QueueUrl: queueUrl,
    MaxNumberOfMessages: 1,
    WaitTimeSeconds: 20
  };

  try {
    const data = await sqs.receiveMessage(params).promise();
    if (data.Messages && data.Messages.length > 0) {
      for (const message of data.Messages) {
        console.log('Message received:', message);

        // Decrypt the message
        const decryptedData = await decryptMessage(message.Body);

        // Process the decrypted data (pass to the consumer task running inside the enclave)
        await processData(decryptedData);

        // Delete the message from the queue
        await deleteMessage(message.ReceiptHandle);
      }
    }
  } catch (err) {
    console.error('Error polling SQS:', err);
  }
}

// Function to decrypt a message using AWS KMS
async function decryptMessage(encryptedMessage) {
  const params = {
    CiphertextBlob: Buffer.from(encryptedMessage, 'base64')
  };

  try {
    const data = await kms.decrypt(params).promise();
    const decryptedMessage = data.Plaintext.toString('utf-8');
    console.log('Decrypted message:', decryptedMessage);
    return JSON.parse(decryptedMessage);
  } catch (err) {
    console.error('Error decrypting message:', err);
    throw err;
  }
}

// Function to process decrypted data
async function processData(data) {
  try {
    // Here you would call the consumer task running inside the enclave
    const response = await axios.post('http://localhost/process', data);
    console.log('Consumer task response:', response.data);
  } catch (err) {
    console.error('Error processing data:', err);
    throw err;
  }
}

// Function to delete a message from the SQS queue
async function deleteMessage(receiptHandle) {
  const params = {
    QueueUrl: queueUrl,
    ReceiptHandle: receiptHandle
  };

  try {
    await sqs.deleteMessage(params).promise();
    console.log('Message deleted:', receiptHandle);
  } catch (err) {
    console.error('Error deleting message:', err);
    throw err;
  }
}

// Start polling the SQS queue
console.log('Starting to poll SQS queue...');
pollQueue();
setInterval(pollQueue, 30000); // Poll the queue every 30 seconds
