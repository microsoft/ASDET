# Feature Engineering

What is feature engineering? When dealing with large data, it is often impossible to develop models that use the entirety of the features available to us in the feature space. We use, so undergo something called feature engineering to pick and choose the most important features.  However, when dealing with unknown data, it is often time consuming to pick and choose the most important features, so we developed a programmatic way to reduce the dimensionality of a dataset by picking features that are relevant to us.
Our toolset is composed of two broad areas: the data cleaning toolkit and the data signature toolkit.  The data cleaning toolkit is composed of several functions that were able to reduce datasets by ~50%

## Data Cleaning Toolkit

*	Dimensionality reduction using entropy-based thresholds
*	Dimensionality reduction using variance-based thresholds
*	Invariant column removal
*	Duplicate column removal
*	Table Binarization Mapping
*	Continuous value removal

## Data Signature

The data signature toolkit builds on the binarizing mapping by assigning a “signature” to each unique row of binary values, where the 1’s represent a present value in that column and a 0 represents an absent value in that column. For example, 1100 would indicate that the first two columns are filled in and the last two columns are not.  We can use data signatures to learn more about the 

*   Underlying feature distributions under the signature
*	Anomalous data signatures based on frequency and value
*	Optimal pivot columns
*	Unique values that can be used to identify certain data signatures

## Feature Distribution

A standalone example of how visualizations for a feature set is distributed can be created