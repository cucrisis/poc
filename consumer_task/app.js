const express = require('express');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();
app.use(bodyParser.json());

// Endpoint to receive and process data
app.post('/process', (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).send('Data is required');
  }

  try {
    // Perform the task (for example, reverse the string)
    const processedData = reverseString(data);
    console.log('Processed data:', processedData);

    res.status(200).send({ processedData });
  } catch (err) {
    console.error('Error processing data:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Function to reverse a string
function reverseString(str) {
  return str.split('').reverse().join('');
}

// Start the server
const port = process.env.PORT || 8888;
app.listen(port, () => {
  console.log(`Consumer task running on port ${port}`);
});
