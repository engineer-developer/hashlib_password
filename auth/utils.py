import hashlib
import uuid
import asyncio

PASSWORD = "secret_password"


async def make_hashed_password(
    password: str,
    salt: str | None = None,
) -> tuple[str, str]:
    """Make hashed password from given password"""

    if not salt:
        salt = uuid.uuid4().hex
    mix = (password + salt).encode()
    hashed_password = hashlib.sha512(mix).hexdigest()
    return hashed_password, salt


async def is_correct_password(
    hashed_password: str,
    salt: str,
    password: str,
) -> bool:
    """Check equality given password with hashed password"""

    result = await make_hashed_password(password, salt)
    return hashed_password == result[0]


async def main() -> None:
    hashed_password, salt = await make_hashed_password(password=PASSWORD)

    check_result = await is_correct_password(
        hashed_password=hashed_password,
        salt=salt,
        password="secret_password",
    )
    assert check_result is True
    print(f"{check_result=}")


if __name__ == "__main__":
    asyncio.run(main())
