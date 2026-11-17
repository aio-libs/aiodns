import asyncio
from collections.abc import Callable

import pytest


def pytest_asyncio_loop_factories(
    config: pytest.Config, item: pytest.Item
) -> dict[str, Callable[[], asyncio.AbstractEventLoop]]:
    if item.path.name == 'test_native_deadlines.py':
        return {'selector': asyncio.SelectorEventLoop}

    return {'default': asyncio.new_event_loop}
