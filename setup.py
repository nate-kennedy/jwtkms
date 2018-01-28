from setuptools import setup, find_packages

setup(name='jwtkms',
      version='0.1.0',
      description='A KMS only implementation of JWT',
      url='http://github.com/nate-kennedy/pyjwt-kms',
      author='Nate Kennedy',
      author_email='nate.g.kennedy@gmail.com',
      license='MIT',
      packages=find_packages('jwtkms', exclude=['test']),
      install_requires=['boto3'],
      zip_safe=False)