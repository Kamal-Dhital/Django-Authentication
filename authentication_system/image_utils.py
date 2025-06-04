import os
from io import BytesIO
from PIL import Image
from django.core.files.uploadedfile import InMemoryUploadedFile
import sys
import uuid

def validate_image(image):
    """
    Validate that the uploaded file is a valid image.

    Args:
        image: The uploaded image file

    Returns:
        tuple: (is_valid, error_message)
    """
    if not image:
        return False, "No image file provided."

    # Check file size (5MB max)
    if image.size > 5 * 1024 * 1024:
        return False, "Image file too large. Maximum size is 5MB."

    # Check file type
    allowed_types = ['image/jpeg', 'image/png', 'image/gif']
    if image.content_type not in allowed_types:
        return False, "Invalid file type. Only JPEG, PNG, and GIF are allowed."

    try:
        # Try to open the image to verify it's valid
        img = Image.open(image)
        img.verify()
        return True, "Image is valid."
    except Exception as e:
        return False, f"Invalid image file: {str(e)}"


def process_profile_image(uploaded_image, username):
    """
    Process an uploaded profile image:
    1. Resize to appropriate dimensions
    2. Compress to reduce file size
    3. Generate unique filename

    Args:
        uploaded_image: The uploaded image file
        username: The username to include in the filename

    Returns:
        InMemoryUploadedFile: Processed image ready for saving
    """
    # Open the image
    img = Image.open(uploaded_image)

    # Convert to RGB if needed (in case of PNG with transparency)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    # Resize image to max dimensions while preserving aspect ratio
    max_size = (500, 500)
    img.thumbnail(max_size, Image.LANCZOS)

    # Create a unique filename based on username and uuid
    unique_id = str(uuid.uuid4())[:8]
    filename = f"{username}_{unique_id}.jpg"

    # Save the processed image to a BytesIO buffer
    output = BytesIO()
    img.save(output, format='JPEG', quality=85)
    output.seek(0)

    # Return a Django-friendly file object
    return InMemoryUploadedFile(
        output,
        'ImageField',
        filename,
        'image/jpeg',
        sys.getsizeof(output),
        None
    )
