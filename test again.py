{\rtf1\ansi\ansicpg1252\cocoartf2870
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fmodern\fcharset0 Courier;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\deftab720
\pard\pardeftab720\partightenfactor0

\f0\fs28 \cf0 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 import turtle # Set up the screen canvas window = turtle.Screen() window.bgcolor("white") window.title("Simple Turtle Square") # Create a turtle object and style it my_turtle = turtle.Turtle() my_turtle.shape("turtle") my_turtle.color("blue") my_turtle.speed(3) # Speed levels: 1 (slow) to 10 (fast) # Draw a square using a loop for _ in range(4): my_turtle.forward(100) # Move forward 100 pixels my_turtle.right(90) # Turn right 90 degrees # Keep the window open until you click on it window.exitonclick()}