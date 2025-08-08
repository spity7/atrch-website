import AOS from "aos";
import "aos/dist/aos.css";
import "lightgallery.js/dist/css/lightgallery.css";
import { useEffect } from "react";
import "react-modal-video/scss/modal-video.scss";
import { BrowserRouter as Router, Route, Switch } from "react-router-dom";
import "swiper/components/pagination/pagination.scss";
import "swiper/swiper.scss";
import "./assets/css/animate.css";
import "./assets/css/bootstrap.min.css";
// CSS File Here
import "./assets/css/elegantIcons.css";
import "./assets/css/icofont.css";
import "./assets/scss/style.scss";
import NavScrollTop from "./components/nav-scroll-top";
import AboutPage from "./pages/about";
import Blog from "./pages/blog";
import Contact from "./pages/contact";
import HomePage from "./pages/index";
import Portfolio from "./pages/portfolio";
import VideoGallery from "./pages/video-gallery";
import BlogAuthor from "./templates/blog-author";
import BlogCategory from "./templates/blog-category";
import BlogDate from "./templates/blog-date";
import BlogDetails from "./templates/blog-details";
import BlogTag from "./templates/blog-tag";
import PortfolioDetails from "./templates/portfolio-details";

const App = () => {
    useEffect(() => {
        AOS.init({
            offset: 80,
            duration: 1000,
            once: true,
            easing: "ease",
        });
        AOS.refresh();
    }, []);
    return (
        <Router>
            <NavScrollTop>
                <Switch>
                    <Route
                        path={`${process.env.PUBLIC_URL + "/"}`}
                        exact
                        component={HomePage}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/about"}`}
                        component={AboutPage}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/portfolio"}`}
                        component={Portfolio}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/video-gallery"}`}
                        component={VideoGallery}
                    />
                    <Route
                        path={`${
                            process.env.PUBLIC_URL + "/portfolio-details/:id"
                        }`}
                        component={PortfolioDetails}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/blog"}`}
                        component={Blog}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/category/:slug"}`}
                        component={BlogCategory}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/tag/:slug"}`}
                        component={BlogTag}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/date/:date"}`}
                        component={BlogDate}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/author/:author"}`}
                        component={BlogAuthor}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/blog-details/:id"}`}
                        component={BlogDetails}
                    />
                    <Route
                        path={`${process.env.PUBLIC_URL + "/contact"}`}
                        component={Contact}
                    />
                </Switch>
            </NavScrollTop>
        </Router>
    );
};

export default App;
