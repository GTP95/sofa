import sys
import shutil
from pathlib import Path


def apply_patch():
    try:
        # Import qiling to find its installation path
        import qiling

        # Locate qiling/extensions directory
        qiling_path = Path(qiling.__path__[0])  # Path to qiling package
        extensions_path = qiling_path / "extensions"

        if not extensions_path.exists():
            raise FileNotFoundError(
                f"The 'extensions' directory does not exist in {qiling_path}"
            )

        # Get the absolute path of the script directory
        script_dir = Path(__file__).resolve().parent

        # Path to the qilingpatch folder (assumes it's in the current working directory)
        patch_path = script_dir.parent.parent / "qilingpatch"

        if not patch_path.exists():
            raise FileNotFoundError(
                f"The 'qilingpatch' folder was not found in the current directory: {patch_path}"
            )

        # Copy contents of qilingpatch to qiling/extensions
        for item in patch_path.iterdir():
            target = extensions_path / item.name
            if item.is_dir():
                # Copy entire directory
                shutil.copytree(item, target, dirs_exist_ok=True)
            else:
                # Copy individual file
                shutil.copy2(item, target)

        print(f"Successfully applied patch from {patch_path} to {extensions_path}")

    except ImportError:
        print(
            "Error: qiling package is not installed. Please install it first using pip."
        )
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    apply_patch()
