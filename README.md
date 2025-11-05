# GATEKEEPER

The GateKeeper is an application for distributing a backend application to clients. The main idea is to provide one individual instance per user. This is very important because the backend application is a web interface for a non-stateless application. Because of that, it is essential to provide a handler to manage the instances and make a reservation.

When the client hits this application endpoint, the reservation is done using a unique ID stored in a cookie. This unique ID is used for routing to the backend target. The backend target is chosen from a pool of free services, locked with this unique ID, and stored in the Redis DB.

The instance is limited to one hour of user inactivity. When it happens, the backend is freed and the lock record in the DB is removed.
