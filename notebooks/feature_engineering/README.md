# Feature Engineering

What is feature engineering? When dealing with large datasets, it is often impossible to develop models that use the entirety of the features (columns within the dataset) available to us in the feature space. We use feature engineering to pick and choose the most important features.  However, when dealing with unknown data, it is often time consuming to pick and choose the most important features, so we developed a programmatic way to reduce the dimensionality of a dataset by picking features that are relevant to us.

Our toolset is composed of two broad areas: the data cleaning toolkit and the data signature toolkit.  The data cleaning toolkit is composed of several functions that were able to reduce features (columns) in datasets by approximately 50%

## Data Cleaning Toolkit

The cleanTable module contains functions for the following tasks:

To clean the table automatically, we can simply import our module and call our function on our Pandas DataFrame.

```
from utils import cleanTable
result = cleanTable(df)
```

*	Dimensionality reduction using entropy-based thresholds
*	Invariant column removal
*	Duplicate column removal
*	Table Binarization Mapping
*	Regular expression-based pruning

## Data Signature

To call the function you can simple run the following snippet.

```
from signature import DataSignature
data = DataSignature(df)
data.generateSignatures()
data.findUniques()
```

The data signature toolkit builds on the Binarization Mapping function mentioned previously. It works by assigning a “signature” to each unique row of data based on whether columns are populated with data or not. In the binary signature 1’s represent a present value in that column and a 0 represents an absent value in that column. For example, 1100 would indicate that the first two columns are filled in and the last two columns are not.  We can use data signatures to learn more about the following:

*   Underlying feature distributions under the signature
*	Anomalous data signatures based on frequency and value
*	Optimal pivot columns
*	Unique values that can be used to identify certain data signatures

## Feature Distribution

A standalone example of how visualizations for a feature set is distributed can be created