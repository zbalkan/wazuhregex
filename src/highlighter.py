class Highlighter:
    """
    A class responsible for formatting text with ANSI color codes.
    """
    # Class-level constants for colors
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

    def __init__(self, highlight_color=RED):
        """
        Initializes the highlighter with a specific color.

        Args:
            highlight_color (str): The ANSI escape code for highlighting.
        """
        self.highlight_color = highlight_color

    def apply(self, text: str, spans: list[tuple[int, int]]) -> str:
        """
        Applies highlighting to a string based on a list of spans.

        Args:
            text (str): The original text.
            spans (list): A list of (start, end) tuples indicating where to apply color.

        Returns:
            str: The formatted string with ANSI color codes.
        """
        if not spans:
            return text

        # To handle multiple spans correctly without overlapping, we build the
        # string piece by piece. For this tool, we only get one span.
        span = spans[0]
        start, end = span

        return f"{text[:start]}{self.highlight_color}{text[start:end]}{self.ENDC}{text[end:]}"