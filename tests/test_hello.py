"""Tests for the GCP IAM Threat Detection Lab application."""

import pytest
from app import hello


def test_hello():
    """Test the hello function returns the expected greeting."""
    result = hello()
    assert result == "Hello from GCP IAM Threat Detection Lab!"
    assert isinstance(result, str)
    assert len(result) > 0
