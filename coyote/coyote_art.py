"""ASCII art for the Coyote character with different poses."""

from __future__ import annotations

from enum import Enum


class CoyotePose(Enum):
    IDLE = "idle"
    ALERT = "alert"
    SCANNING = "scanning"
    ALL_CLEAR = "all_clear"


# Howling/sitting coyote - iconic silhouette
POSES: dict[CoyotePose, str] = {
    CoyotePose.IDLE: r"""
                       .
                      /|
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / o       <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /   \_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
""".strip("\n"),

    CoyotePose.ALERT: r"""
                       . !
                      /|
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / O    !  <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /^^^\_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
""".strip("\n"),

    CoyotePose.SCANNING: r"""
                       .     ~
                      /|    ~
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / -       <   |
            /  _______/    |
           |  /           /
           | |     ___   /
           | |    /   \_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
""".strip("\n"),

    CoyotePose.ALL_CLEAR: r"""
                       .
                      /|
                     / |  /|
               /\   /  | / |
              /  \_/   |/  |
             / ^       <   |
            /  __\_w_//    |
           |  /           /
           | |     ___   /
           | |    /   \_/
           | |   |
      /\   | |   |
     /  \__| |   |
    /       \|   |
   /              \
  |    |     |     |
  |____|     |_____|
""".strip("\n"),
}

# Compact version - front-facing coyote head with body
POSES_COMPACT: dict[CoyotePose, str] = {
    CoyotePose.IDLE: r"""
     /|      |\
    / |      | \
   |   \    /   |
   |    \  /    |
   |  o  \/  o  |
   |     /\     |
    \   /  \   /
     | | <> | |
     |  \__/  |
      \_|  |_/
        |  |
       _|  |_
      |_|  |_|
""".strip("\n"),

    CoyotePose.ALERT: r"""
     /|  !!  |\
    / |      | \
   |   \    /   |
   |    \  /    |
   |  O  \/  O  |
   |     /\     |
    \   /^^\   /
     | | <> | |
     |  \__/  |
      \_|  |_/
        |  |
       _|  |_
      |_|  |_|
""".strip("\n"),

    CoyotePose.SCANNING: r"""
     /|      |\ ~
    / |      | \~
   |   \    /   |
   |    \  /    |
   |  -  \/  -  |
   |     /\     |
    \   /  \   /
     | | <> | |
     |  \__/  |
      \_|  |_/
        |  |
       _|  |_
      |_|  |_|
""".strip("\n"),

    CoyotePose.ALL_CLEAR: r"""
     /|      |\
    / |      | \
   |   \    /   |
   |    \  /    |
   |  ^  \/  ^  |
   |     /\     |
    \   /  \   /
     | |\__/| |
     |  \w /  |
      \_|  |_/
        |  |
       _|  |_
      |_|  |_|
""".strip("\n"),
}


QUOTES: dict[CoyotePose, list[str]] = {
    CoyotePose.IDLE: [
        "Watching...",
        "On the prowl.",
        "Eyes open.",
        "Waiting...",
    ],
    CoyotePose.ALERT: [
        "Found something!",
        "Sniffed out issues!",
        "Alert! Alert!",
        "Caught a scent!",
    ],
    CoyotePose.SCANNING: [
        "Scanning...",
        "Sniffing around...",
        "Checking files...",
        "On the trail...",
    ],
    CoyotePose.ALL_CLEAR: [
        "All clear!",
        "Looks clean!",
        "No threats found.",
        "Territory secure.",
    ],
}


def get_art(pose: CoyotePose, compact: bool = False) -> str:
    """Get the ASCII art for a given pose."""
    if compact:
        return POSES_COMPACT[pose]
    return POSES[pose]


def get_quote(pose: CoyotePose, index: int = 0) -> str:
    """Get a quote for a given pose."""
    quotes = QUOTES[pose]
    return quotes[index % len(quotes)]
