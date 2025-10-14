from langchain.tools import tool
from typing import List, Callable, Literal, Optional
import requests
import os
from pydantic import BaseModel, Field

####################################
# Tools
####################################
financial_datasets_api_key = os.getenv("FINANCIAL_DATASETS_API_KEY")

class FinancialStatementsInput(BaseModel):
    ticker: str = Field(description="The stock ticker symbol to fetch financial statements for. For example, 'AAPL' for Apple.")
    period: Literal["annual", "quarterly", "ttm"] = Field(description="The reporting period for the financial statements. 'annual' for yearly, 'quarterly' for quarterly, and 'ttm' for trailing twelve months.")
    limit: int = Field(default=10, description="The number of past financial statements to retrieve.")
    report_period_gt: Optional[str] = Field(default=None, description="Optional fitler to retrieve financial statements greater than the specified report period.")
    report_period_gte: Optional[str] = Field(default=None, description="Optional fitler to retrieve financial statements greater than or equal to the specified report period.")
    report_period_lt: Optional[str] = Field(default=None, description="Optional fitler to retrieve financial statements less than the specified report period.")
    report_period_lte: Optional[str] = Field(default=None, description="Optional fitler to retrieve financial statements less than or equal to the specified report period.")


def _create_params(
    ticker: str,
    period: Literal["annual", "quarterly", "ttm"],
    limit: int,
    report_period_gt: Optional[str],
    report_period_gte: Optional[str],
    report_period_lt: Optional[str],
    report_period_lte: Optional[str]
) -> dict:
    """Helper function to create params dict for API calls."""
    params = {"ticker": ticker, "period": period, "limit": limit}
    if report_period_gt is not None:
        params["report_period_gt"] = report_period_gt
    if report_period_gte is not None:
        params["report_period_gte"] = report_period_gte
    if report_period_lt is not None:
        params["report_period_lt"] = report_period_lt
    if report_period_lte is not None:
        params["report_period_lte"] = report_period_lte
    return params

def call_api(endpoint: str, params: dict) -> dict:
    """Helper function to call the Financial Datasets API."""
    base_url = "https://api.financialdatasets.ai"
    url = f"{base_url}{endpoint}"
    headers = {"x-api-key": financial_datasets_api_key}
    response = requests.get(url, params=params, headers=headers)
    response.raise_for_status()
    return response.json()

@tool(args_schema=FinancialStatementsInput)
def get_income_statements(
    ticker: str,
    period: Literal["annual", "quarterly", "ttm"],
    limit: int = 10,
    report_period_gt: Optional[str] = None,
    report_period_gte: Optional[str] = None,
    report_period_lt: Optional[str] = None,
    report_period_lte: Optional[str] = None
) -> dict:
    """Fetches a company's income statement, detailing its revenues, expenses, and net income over a reporting period. Useful for evaluating a company's profitability and operational efficiency."""
    params = _create_params(ticker, period, limit, report_period_gt, report_period_gte, report_period_lt, report_period_lte)
    data = call_api("/financials/income-statements/", params)
    return data.get("income_statements", {})

@tool(args_schema=FinancialStatementsInput)
def get_balance_sheets(
    ticker: str,
    period: Literal["annual", "quarterly", "ttm"],
    limit: int = 10,
    report_period_gt: Optional[str] = None,
    report_period_gte: Optional[str] = None,
    report_period_lt: Optional[str] = None,
    report_period_lte: Optional[str] = None
) -> dict:
    """Retrieves a company's balance sheet, which provides a snapshot of its assets, liabilities, and shareholders' equity at a specific point in time. Essential for assessing a company's financial position."""
    params = _create_params(ticker, period, limit, report_period_gt, report_period_gte, report_period_lt, report_period_lte)
    data = call_api("/financials/balance-sheets/", params)
    return data.get("balance_sheets", {})

@tool(args_schema=FinancialStatementsInput)
def get_cash_flow_statements(
    ticker: str,
    period: Literal["annual", "quarterly", "ttm"],
    limit: int = 10,
    report_period_gt: Optional[str] = None,
    report_period_gte: Optional[str] = None,
    report_period_lt: Optional[str] = None,
    report_period_lte: Optional[str] = None
) -> dict:
    """Provides a company's cash flow statement, showing how cash is generated and used across operating, investing, and financing activities. Key for understanding a company's liquidity and solvency."""
    params = _create_params(ticker, period, limit, report_period_gt, report_period_gte, report_period_lt, report_period_lte)
    data = call_api("/financials/cash-flow-statements/", params)
    return data.get("cash_flow_statements", {})

TOOLS: List[Callable[..., any]] = [
    get_income_statements,
    get_balance_sheets,
    get_cash_flow_statements,
]

RISKY_TOOLS = {}  # guardrail: require confirmation