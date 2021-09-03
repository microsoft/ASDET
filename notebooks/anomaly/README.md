# Notebooks for Anomaly Detection

## Isolation Forest

The Isolation Forest notebook contains the process to identify anomalies in a multivariate count based format of user selected entities, features and time range of databases from Azure Sentinel. It makes use of the Isolation Forest algorithm to do so and visualizes the anomalous outputs for the "OfficeActivity" table through histograms, scatter plots and pairplots

## Time Series

The multivariate time series notebook contains an example of detecting anomalies in multivariate time series data. This notebook relies on the time series modules created by the MSTICpy team. Provided a table, a timeframe, and a set of features the notebook generates a set of anomalous features within that timeframe. It then allows the user to visualize the specific features that are anomalous.
