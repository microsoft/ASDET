# Modified Timeseries Utilities From MSTICpy

import pandas as pd

from typing import Any, List, Dict

try:
    from scipy import stats
    from statsmodels.tsa.seasonal import STL
except ImportError as imp_err:
    raise MsticpyImportExtraError(
        "Cannot use this feature without scipy and statsmodel installed",
        title="Error importing package",
        extra="ml",
    ) from imp_err
    
_DEFAULT_KWARGS = ["seasonal", "period", "score_threshold"]

def check_kwargs(supplied_args: Dict[str, Any], legal_args: List[str]):
    """
    Check all kwargs names against a list.
    Parameters
    ----------
    supplied_args : Dict[str, Any]
        Arguments to check
    legal_args : List[str]
        List of possible arguments.
    Raises
    ------
    NameError
        If any of the arguments are not legal. If the an arg is
        a close match to one or more `legal_args`, these are
        returned in the exception.
    """
    name_errs = []
    for name in supplied_args:
        try:
            check_kwarg(name, legal_args)
        except NameError as err:
            name_errs.append(err)
    if name_errs:
        raise NameError(name_errs)

def ts_anomalies_stl(data: pd.DataFrame, **kwargs) -> pd.DataFrame: 
    """
    Return anomalies in Timeseries using STL.

    Parameters
    ----------
    data : pd.DataFrame
        DataFrame as a time series data set retrived from data connector or
        external data source. Dataframe must have 2 columns with time column
        set as index and other numeric value.

    Other Parameters
    ----------------
    seasonal : int, optional
        Seasonality period of the input data required for STL.
        Must be an odd integer, and should normally be >= 7 (default).
    period: int, optional
        Periodicity of the the input data. by default 24 (Hourly).
    score_threshold : float, optional
        standard deviation threshold value calculated using Z-score used to
        flag anomalies, by default 3

    Returns
    -------
    pd.DataFrame
        Returns a dataframe with additional columns by decomposing time series data
        into residual, trend, seasonal, weights, baseline, score and anomalies.
        The anomalies column will have 0, 1,-1 values based on score_threshold set.

    Raises
    ------
    MsticpyException
        If input data is not a pandas dataframe
        If the index is not set to a datetime type
        If the time range of the input data is not beyond the minimum required.

    Notes
    -----
    The decomposition method is STL - Seasonal-Trend Decomposition using LOESS

    """
    check_kwargs(kwargs, _DEFAULT_KWARGS)
    seasonal: int = kwargs.get("seasonal", 7)
    period: int = kwargs.get("period", 24)
    score_threshold: float = kwargs.get("score_threshold", 3.0)

    if not isinstance(data, pd.DataFrame):
        raise MsticpyException("input data should be a pandas dataframe")
    
    if not pd.api.types.is_datetime64_any_dtype(data.index.dtype):
        raise MsticpyException(
            "Input data index must be the datatime value",
            "input_df = input_df.set_index('Timestamp_col')"
        )
    # @Ashwin - not sure what the min range should be here
    if data.index.max() - data.index.min() <= pd.Timedelta(f"{period}H"):
        raise MsticpyException(
            f"Input data time range must be greater than {period} hours",
        )

    # STL method does Season-Trend decomposition using LOESS.
    # Accepts timeseries dataframe
    stl = STL(data, seasonal=seasonal, period=period)
    # Fitting the data - Estimate season, trend and residuals components.
    res = stl.fit()
    result = data.copy()
    # Create dataframe columns from decomposition results
    result["residual"] = res.resid
    result["trend"] = res.trend
    result["seasonal"] = res.seasonal
    result["weights"] = res.weights
    result["anomalies"] = 0  # preset anomalies and score to 0
    result["score"] = 0
    # Baseline is generally seasonal + trend
    result["baseline"] = result["seasonal"] + result["trend"]
    # Type cast and replace na values with 0
    result = result.fillna(0).astype("int64")
    # Calculate zscore based on residual column
    # this column does not contain seasonal/trend components
    result["score"] = stats.zscore(result["residual"])
    result["score"] = result["score"].fillna(0)  # replace any NA zscore to 0

    # create spikes(1) and dips(-1) based on threshold and seasonal columns
    result.loc[
        (result["score"] > score_threshold) & (result["seasonal"] > 0), "anomalies"
    ] = 1
    result.loc[
        (result["score"] > score_threshold) & (result["seasonal"] < 0), "anomalies"
    ] = -1
    result.loc[(result["score"] < score_threshold), "anomalies"] = 0

    # Datatype casting
    result["anomalies"] = result["anomalies"].astype("int64")
    result = result.reset_index()
    return result
