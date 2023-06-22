"""
Original code from: @15Galan
"""

# Módulos necesarios
import io


class ProgressBar:
    """
    This class represents a progress bar and it's state.
    """

    def __init__(self, total=100):
        """
        Constructor.
        It creates a progress bar with a maximum value.

        :param total: the maximum value of the progress bar (default: 100).
        """
        self.state = 0
        self.total = total

    def expand(self, units):
        """
        Expands the progress bar total value.
        Useful when the total value is unknown at the beginning.

        :param units: number of units to expand the progress bar.
        """
        self.total += units

    def update(self, step=1, info=''):
        """
        Updates the progress bar and its information message.
        Normal behaviour of any progress: adds a step until 100 %.

        :param step: number of units to add to the progress bar (default: 1).
        :param info: message to display next to the progress bar (default: none).
        """
        self.state += step

        # Check if the progress is over 100 %
        if self.state > self.total:
            self.state = self.total

        print(self, '\t' + info, end='' if self.state < self.total else '\n')

    def finish(self, info=''):
        """
        Set the progress to 100 % and display the information message.
        Useful when the progress must end before reaching 100 % or to
        display a final message.

        :param info: message to display next to the progress bar (default: none).
        """

        self.state = self.total  # Set the progress to 100 %

        print(self, '\t' + info, end='' if self.state < self.total else '\n')

    def __str__(self):
        """
        Returns the progress bar as a string.
        """
        bar = io.StringIO()

        # Compute the percentage of the progress
        percentage = self.state / self.total

        # Compute the number of filled and empty spaces in the progress bar
        filled = int(percentage * 50)
        spaces = 50 - filled

        # Display the progress bar
        bar.write('\r[')
        bar.write('#' * filled)
        bar.write(' ' * spaces)
        bar.write('] ')
        bar.write(str(int(percentage * 100)))
        bar.write('%')

        return bar.getvalue()
