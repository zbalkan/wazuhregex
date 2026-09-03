class Highlighter:
    """
    A class responsible for formatting text with ANSI color codes.
    """
    # Class-level constants for colors
    RED = '\033[91m'
    ENDC = '\033[0m'

    def __init__(self, highlight_color: str = RED) -> None:
        """
        Initializes the highlighter with a specific color.

        Args:
            highlight_color (str): The ANSI escape code for highlighting.
        """
        self.highlight_color: str = highlight_color

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

        ordered = sorted(spans)
        text_length = len(text)
        previous_end = 0
        overlaps = False
        for start, end in ordered:
            if not 0 <= start <= end <= text_length:
                raise ValueError(f"Invalid highlight span: {(start, end)}")
            if start < previous_end:
                overlaps = True
            previous_end = max(previous_end, end)

        if overlaps:
            # Preserve the historical behavior for arbitrary caller-supplied
            # overlapping spans. Regex finditer results are non-overlapping, so
            # normal CLI use takes the linear construction path below.
            highlighted = text
            for start, end in reversed(ordered):
                highlighted = (
                    f"{highlighted[:start]}{self.highlight_color}"
                    f"{highlighted[start:end]}{self.ENDC}{highlighted[end:]}"
                )
            return highlighted

        # Construct once rather than repeatedly slicing an ever-growing string.
        # For K non-overlapping spans this is O(N + K log K), dominated by the
        # sort, instead of O(N*K) repeated reconstruction.
        pieces: list[str] = []
        cursor = 0
        for start, end in ordered:
            pieces.append(text[cursor:start])
            pieces.append(self.highlight_color)
            pieces.append(text[start:end])
            pieces.append(self.ENDC)
            cursor = end
        pieces.append(text[cursor:])
        return ''.join(pieces)
