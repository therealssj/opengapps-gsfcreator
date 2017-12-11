from setuptools import setup, find_packages

setup(
      name='opengapps-gsfcreator',
      version='0.0.1',
      description='CLI to make the task of creating gsf ids easier',
      author='Mehul Gupta(therealssj)',
      author_email='mehul.guptagm@gmail.com',
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'gsfcreator = gsfcreator.cli:cli',
          ]
      },
      url='https://github.com/therealssj/opengapps-gsfcreator',
      keywords=['gsfcreator', 'cli', 'command-line', 'python', 'opengapps'],
      license='MIT',
      classifiers=[],
      install_requires=[
            'click'
      ]
)