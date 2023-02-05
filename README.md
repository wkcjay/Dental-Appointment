# Dental-Appointment System
## Objective
This project is to create a prototype of an application, Dental Appointment System, mainly focusing on the backend development using GoLang in a Client-Server Setup
## Features
### For Client:
### Login Feature
1. New Patient Sign Up
  - User signs up with Username and Password
  - Username and Passowrd is stored in the server as a hash value
2. Existing Returning Patient
  - User signs in with Username and Password
  - Server compares using hash values
3. Admin Sign In
  - Admin signs in with the following default credentials
    - Username: "admin"
    - Password: "password"
### Customer Page
1. Search for available appointments
  - Server maintains and sends available appointmnts via JSON
  - Templates will be used for front end with .gohtml extensio
2. Book appointment
  - User will have inputs in a Form to select and book appointments
  - User selection will be sent to the Server and update the appointment slots
3. Edit appointment details
  - User able to retrieve own booking and edit appointments
4. Edit Customer Info
  - User able to update new password
### Admin Page
1. Edit appointment details
  - Admin able to view all bookings and make changes via Form
2. Delete Sessions
  - Admin able to view and delete sessions stored on Server
3. Delete Users
  - Admin able to view and delete user accounts stored on Server
### For Server:
### Login Process
1. Issue cookies to new logins
2. Store Session mapped to User information
3. Store User information (using data structure for storage)
### Venue Data Process
1. Store appointment availability
2. Store booked appointment details (using data structure for storage)


