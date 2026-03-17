from pydantic import BaseModel
from typing import Literal


class CvssInput(BaseModel):
    AV: Literal["N", "A", "L", "P"]
    AC: Literal["L", "H"]
    PR: Literal["N", "L", "H"]
    UI: Literal["N", "R"]
    S: Literal["U", "C"]
    C: Literal["H", "L", "N"]
    I: Literal["H", "L", "N"]
    A: Literal["H", "L", "N"]


class CvssResult(BaseModel):
    score: float
    vector: str
    severity: str
