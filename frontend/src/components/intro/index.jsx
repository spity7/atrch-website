import PropTypes from "prop-types";
import { Link } from "react-router-dom";
const Intro = ({ data }) => {
    return (
        <div
            className="intro-section section overlay"
            // style={{
            //     backgroundImage: `url(${
            //         process.env.PUBLIC_URL + data.backgroundImage
            //     })`,
            // }}
        >
            <img
                src={process.env.PUBLIC_URL + data.backgroundImage}
                alt="background"
                style={{
                    width: "100%",
                    height: "100vh",
                    objectFit: "cover",
                    position: "absolute",
                    top: 0,
                    left: 0,
                    zIndex: -1,
                }}
            />
            <div className="container">
                <div className="row row-cols-lg-1 row-cols-1">
                    <div className="col align-self-center">
                        <div className="intro-content">
                            {/* <span className="sub-title">{data.subTitle}</span> */}
                            <h2 className="title">{data.title}</h2>
                            {/* <div className="desc">
                                <p>{data.desc}</p>
                            </div> */}
                            {/* <Link
                                to={process.env.PUBLIC_URL + "/"}
                                className="intro-btn"
                            >
                                {data.buttonText}
                            </Link> */}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

Intro.propTypes = {
    data: PropTypes.object,
};

export default Intro;
